const crypto = require("crypto");

const BLOCK_SIZE = 64; // bytes for SHA-256

function hmacSha256(key, message) {
  if (!Buffer.isBuffer(key)) key = Buffer.from(key);
  if (!Buffer.isBuffer(message)) message = Buffer.from(message);

  if (key.length > BLOCK_SIZE) {
    key = crypto.createHash("sha256").update(key).digest();
  }
  if (key.length < BLOCK_SIZE) {
    const pad = Buffer.alloc(BLOCK_SIZE - key.length, 0);
    key = Buffer.concat([key, pad]);
  }

  const oKeyPad = Buffer.alloc(BLOCK_SIZE);
  const iKeyPad = Buffer.alloc(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    oKeyPad[i] = key[i] ^ 0x5c;
    iKeyPad[i] = key[i] ^ 0x36;
  }

  const inner = crypto.createHash("sha256").update(Buffer.concat([iKeyPad, message])).digest();
  const outer = crypto.createHash("sha256").update(Buffer.concat([oKeyPad, inner])).digest();
  return outer;
}

module.exports = { hmacSha256 };
