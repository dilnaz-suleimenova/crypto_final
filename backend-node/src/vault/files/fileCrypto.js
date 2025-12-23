const crypto = require("crypto");
const { deriveMasterKey } = require("./kdf");
const { hmacSha256 } = require("../../crypto/hmacCustom");
const { sha256, sha256Hex } = require("../core_crypto/hash");

function aesGcmEncryptStream(key, plaintextBuf, aadBuf) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  if (aadBuf) cipher.setAAD(aadBuf);
  // streaming-friendly: update can be called chunk-by-chunk
  const CHUNK = 64 * 1024;
  const outChunks = [];
  for (let off = 0; off < plaintextBuf.length; off += CHUNK) {
    outChunks.push(cipher.update(plaintextBuf.subarray(off, off + CHUNK)));
  }
  outChunks.push(cipher.final());
  const ciphertext = Buffer.concat(outChunks);
  const tag = cipher.getAuthTag();
  return { nonce, ciphertext, tag };
}

function aesGcmDecryptStream(key, nonce, ciphertextBuf, tag, aadBuf) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  if (aadBuf) decipher.setAAD(aadBuf);
  decipher.setAuthTag(tag);
  const CHUNK = 64 * 1024;
  const outChunks = [];
  for (let off = 0; off < ciphertextBuf.length; off += CHUNK) {
    outChunks.push(decipher.update(ciphertextBuf.subarray(off, off + CHUNK)));
  }
  outChunks.push(decipher.final());
  return Buffer.concat(outChunks);
}

/**
 * Encrypt file data:
 * - derive master key from vault_password (PBKDF2)
 * - generate random FEK (data key)
 * - wrap FEK with master key (AES-GCM)
 * - encrypt file bytes with FEK (AES-GCM)
 * - compute integrity: HMAC(ciphertext) + sha256(plaintext)
 */
function encryptFile({ userId, vaultPassword, filename, plaintext }) {
  const salt = crypto.randomBytes(16);
  const masterKey = deriveMasterKey(vaultPassword, salt);

  const fek = crypto.randomBytes(32);
  const wrapAad = Buffer.from(`wrap:${userId}`, "utf8");
  const wrapped = aesGcmEncryptStream(masterKey, fek, wrapAad);

  const fileAad = Buffer.from(JSON.stringify({ userId, filename }), "utf8");
  const enc = aesGcmEncryptStream(fek, plaintext, fileAad);

  const hmac = hmacSha256(masterKey, enc.ciphertext); // custom HMAC (from scratch)
  const plainHash = sha256(plaintext);

  return {
    meta: {
      filename,
      user_id: userId,
      created_at: new Date().toISOString(),
      pbkdf2_salt_b64: salt.toString("base64"),
      wrapped_fek: {
        nonce_b64: wrapped.nonce.toString("base64"),
        tag_b64: wrapped.tag.toString("base64"),
        ciphertext_b64: wrapped.ciphertext.toString("base64")
      },
      file_nonce_b64: enc.nonce.toString("base64"),
      file_tag_b64: enc.tag.toString("base64"),
      hmac_b64: hmac.toString("base64"),
      plaintext_sha256_hex: plainHash.toString("hex"),
      ciphertext_sha256_hex: sha256Hex(enc.ciphertext)
    },
    ciphertext: enc.ciphertext
  };
}

/**
 * Decrypt file data with strict integrity-before-decrypt:
 * - derive master key
 * - verify HMAC(ciphertext)
 * - unwrap FEK
 * - decrypt ciphertext with FEK (AEAD tag verified by library)
 * - verify plaintext SHA-256
 */
function decryptFile({ userId, vaultPassword, meta, ciphertext }) {
  const salt = Buffer.from(meta.pbkdf2_salt_b64, "base64");
  const masterKey = deriveMasterKey(vaultPassword, salt);

  // 1) Integrity BEFORE decrypt (Encrypt-then-MAC principle)
  const expectedHmac = Buffer.from(meta.hmac_b64, "base64");
  const actualHmac = hmacSha256(masterKey, ciphertext);
  if (!crypto.timingSafeEqual(expectedHmac, actualHmac)) {
    const err = new Error("Integrity check failed (HMAC mismatch)");
    err.code = "TAMPER";
    throw err;
  }

  // 2) Unwrap FEK
  const wrap = meta.wrapped_fek;
  const wrapNonce = Buffer.from(wrap.nonce_b64, "base64");
  const wrapTag = Buffer.from(wrap.tag_b64, "base64");
  const wrapCt = Buffer.from(wrap.ciphertext_b64, "base64");
  const wrapAad = Buffer.from(`wrap:${userId}`, "utf8");
  const fek = aesGcmDecryptStream(masterKey, wrapNonce, wrapCt, wrapTag, wrapAad);

  // 3) Decrypt file (AEAD verifies tag)
  const nonce = Buffer.from(meta.file_nonce_b64, "base64");
  const tag = Buffer.from(meta.file_tag_b64, "base64");
  const fileAad = Buffer.from(JSON.stringify({ userId, filename: meta.filename }), "utf8");
  const plaintext = aesGcmDecryptStream(fek, nonce, ciphertext, tag, fileAad);

  // 4) Verify plaintext hash
  const plainHashHex = sha256(plaintext).toString("hex");
  if (plainHashHex !== meta.plaintext_sha256_hex) {
    const err = new Error("Integrity check failed (plaintext hash mismatch)");
    err.code = "TAMPER";
    throw err;
  }

  return plaintext;
}

module.exports = { encryptFile, decryptFile };
