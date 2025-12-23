const crypto = require("crypto");

function aesGcmEncrypt(key, plaintext, aad = null) {
  if (!Buffer.isBuffer(key)) key = Buffer.from(key);
  if (!Buffer.isBuffer(plaintext)) plaintext = Buffer.from(plaintext);
  if (key.length !== 32) {
    throw new Error("AES-256 key must be 32 bytes");
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext: enc, tag };
}

function aesGcmDecrypt(key, iv, ciphertext, tag, aad = null) {
  if (!Buffer.isBuffer(key)) key = Buffer.from(key);
  if (!Buffer.isBuffer(iv)) iv = Buffer.from(iv);
  if (!Buffer.isBuffer(ciphertext)) ciphertext = Buffer.from(ciphertext);
  if (!Buffer.isBuffer(tag)) tag = Buffer.from(tag);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  if (aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return dec;
}

module.exports = { aesGcmEncrypt, aesGcmDecrypt };
