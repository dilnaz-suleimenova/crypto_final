const test = require("node:test");
const assert = require("node:assert/strict");

const { MerkleTree } = require("../src/vault/core_crypto/merkle");
const { modExp } = require("../src/vault/core_crypto/modexp");
const { caesarEncrypt, caesarDecrypt } = require("../src/vault/core_crypto/caesar");
const { encryptFile, decryptFile } = require("../src/vault/files/fileCrypto");
const { sendMessage, readAndDecrypt } = require("../src/vault/messaging/service");
const { getState, validateChain, logEvent, minePending } = require("../src/vault/ledger/blockchain");

test("modExp matches JS pow for small values", () => {
  for (let b = 2; b < 10; b++) {
    for (let e = 0; e < 50; e++) {
      for (let m = 2; m < 50; m++) {
        const expected = BigInt(b) ** BigInt(e) % BigInt(m);
        assert.equal(modExp(b, e, m), expected);
      }
    }
  }
});

test("Merkle proof verifies", () => {
  const leaves = ["a", "b", "c", "d", "e"];
  const tree = new MerkleTree(leaves);
  const root = tree.root().toString("hex");
  for (let i = 0; i < leaves.length; i++) {
    const proof = tree.getProof(i);
    assert.equal(MerkleTree.verifyProof(leaves[i], i, proof, root), true);
  }
});

test("Caesar encrypt/decrypt roundtrip", () => {
  const text = "Hello World";
  const ct = caesarEncrypt(text, 5);
  const pt = caesarDecrypt(ct, 5);
  assert.equal(pt, text);
});

test("File encrypt/decrypt roundtrip with integrity", () => {
  const plaintext = Buffer.from("secret file data");
  const { meta, ciphertext } = encryptFile({ userId: 1, vaultPassword: "pw123", filename: "a.txt", plaintext });
  const out = decryptFile({ userId: 1, vaultPassword: "pw123", meta, ciphertext });
  assert.equal(out.toString("utf8"), plaintext.toString("utf8"));
});

test("Secure message send/decrypt verifies signature", () => {
  const record = sendMessage({ senderId: 1, recipientId: 2, message: "hi" });
  const out = readAndDecrypt({ userId: 2, messageId: record.id });
  assert.equal(out.signature_ok, true);
  assert.equal(out.plaintext, "hi");
});

test("Ledger can validate chain", () => {
  // add a couple events, mine, validate
  logEvent({ type: "TEST_EVENT", success: true });
  logEvent({ type: "TEST_EVENT", success: true });
  minePending();
  const v = validateChain();
  assert.equal(v.ok, true);
  const st = getState();
  assert.ok(st.chain.length >= 1);
});
