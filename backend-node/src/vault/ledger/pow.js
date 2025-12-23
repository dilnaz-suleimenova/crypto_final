const { sha256Hex } = require("../core_crypto/hash");

function meetsDifficulty(hashHex, difficulty) {
  return hashHex.startsWith("0".repeat(difficulty));
}

function mineBlockHeader({ prev_hash, timestamp, merkle_root }, difficulty) {
  let nonce = 0;
  while (true) {
    const header = JSON.stringify({ prev_hash, timestamp, merkle_root, nonce });
    const hash = sha256Hex(Buffer.from(header));
    if (meetsDifficulty(hash, difficulty)) {
      return { nonce, hash };
    }
    nonce++;
  }
}

module.exports = { mineBlockHeader, meetsDifficulty };
