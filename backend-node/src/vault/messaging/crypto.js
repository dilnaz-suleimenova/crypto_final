const crypto = require("crypto");

function hkdfSha256(ikm, salt, info, length = 32) {
  // Node.js >= 15: hkdfSync available
  if (typeof crypto.hkdfSync === "function") {
    return crypto.hkdfSync("sha256", ikm, salt, info, length);
  }
  // Fallback HKDF (RFC 5869) using HMAC-SHA256
  const prk = crypto.createHmac("sha256", salt).update(ikm).digest();
  let t = Buffer.alloc(0);
  const okmChunks = [];
  let i = 1;
  while (Buffer.concat(okmChunks).length < length) {
    t = crypto.createHmac("sha256", prk)
      .update(Buffer.concat([t, info, Buffer.from([i])]))
      .digest();
    okmChunks.push(t);
    i++;
  }
  return Buffer.concat(okmChunks).subarray(0, length);
}

function aes256gcmEncrypt(key, plaintext, aad = null) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  if (aad) cipher.setAAD(Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce, ciphertext, tag };
}

function aes256gcmDecrypt(key, nonce, ciphertext, tag, aad = null) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  if (aad) decipher.setAAD(Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

module.exports = { hkdfSha256, aes256gcmEncrypt, aes256gcmDecrypt };
