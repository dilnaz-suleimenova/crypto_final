const { readLedger, writeLedger } = require("./storage");
const { MerkleTree } = require("../core_crypto/merkle");
const { sha256Hex } = require("../core_crypto/hash");
const { mineBlockHeader, meetsDifficulty } = require("./pow");

const DEFAULT_DIFFICULTY = 3; // tweakable
const MAX_PENDING = 5; // mine a block each N events

function nowTs() {
  return Math.floor(Date.now() / 1000);
}

function createGenesis() {
  const timestamp = nowTs();
  const merkle_root = new MerkleTree(["GENESIS"]).root().toString("hex");
  const prev_hash = "0".repeat(64);
  const { nonce, hash } = mineBlockHeader({ prev_hash, timestamp, merkle_root }, DEFAULT_DIFFICULTY);
  return {
    index: 0,
    timestamp,
    prev_hash,
    merkle_root,
    nonce,
    hash,
    difficulty: DEFAULT_DIFFICULTY,
    transactions: [{ type: "GENESIS", timestamp }]
  };
}

function getState() {
  const state = readLedger();
  if (!state.chain || state.chain.length === 0) {
    state.chain = [createGenesis()];
    state.pending = [];
    writeLedger(state);
  }
  return state;
}

function hashBlockHeader(block) {
  const header = JSON.stringify({
    prev_hash: block.prev_hash,
    timestamp: block.timestamp,
    merkle_root: block.merkle_root,
    nonce: block.nonce
  });
  return sha256Hex(Buffer.from(header));
}

function minePending() {
  const state = getState();
  if (!state.pending || state.pending.length === 0) return state;

  const prev = state.chain[state.chain.length - 1];
  const txStrings = state.pending.map((tx) => JSON.stringify(tx));
  const merkle_root = new MerkleTree(txStrings).root().toString("hex");
  const timestamp = nowTs();
  const difficulty = DEFAULT_DIFFICULTY;
  const { nonce, hash } = mineBlockHeader({ prev_hash: prev.hash, timestamp, merkle_root }, difficulty);

  const block = {
    index: state.chain.length,
    timestamp,
    prev_hash: prev.hash,
    merkle_root,
    nonce,
    hash,
    difficulty,
    transactions: state.pending
  };

  state.chain.push(block);
  state.pending = [];
  writeLedger(state);
  return state;
}

function logEvent(event) {
  const state = getState();
  const tx = {
    ...event,
    timestamp: event.timestamp || nowTs()
  };
  state.pending.push(tx);
  writeLedger(state);
  if (state.pending.length >= MAX_PENDING) {
    return minePending();
  }
  return state;
}

function validateChain() {
  const state = getState();
  const chain = state.chain;
  for (let i = 1; i < chain.length; i++) {
    const prev = chain[i - 1];
    const cur = chain[i];
    if (cur.prev_hash !== prev.hash) return { ok: false, error: `Broken link at block ${i}` };
    const calcHash = hashBlockHeader(cur);
    if (calcHash !== cur.hash) return { ok: false, error: `Invalid hash at block ${i}` };
    if (!meetsDifficulty(cur.hash, cur.difficulty)) return { ok: false, error: `PoW failed at block ${i}` };
  }
  return { ok: true };
}

module.exports = { getState, logEvent, minePending, validateChain, hashBlockHeader };
