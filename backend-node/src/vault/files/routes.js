const express = require("express");
const { requireAuth } = require("../../auth/middleware");
const { encryptAndStore, listFiles, decryptFromStore } = require("./service");
const { logEvent } = require("../ledger/blockchain");
const { sha256Hex } = require("../core_crypto/hash");

const router = express.Router();

router.post("/encrypt", requireAuth, (req, res) => {
  try {
    const { vault_password, filename, data_base64 } = req.body || {};
    if (!vault_password || !filename || !data_base64) {
      return res.status(400).json({ detail: "vault_password, filename, data_base64 are required" });
    }
    const record = encryptAndStore({
      userId: req.user.id,
      vaultPassword: vault_password,
      filename,
      dataBase64: data_base64
    });

    logEvent({
      type: "FILE_ENCRYPT",
      user_hash: sha256Hex(Buffer.from(String(req.user.id))),
      file_hash: record.ciphertext_sha256_hex,
      success: true
    });

    return res.json({ file_id: record.id, created_at: record.created_at });
  } catch (e) {
    console.error(e);
    logEvent({ type: "FILE_ENCRYPT", success: false, error: String(e.message || e) });
    return res.status(500).json({ detail: "Failed to encrypt file" });
  }
});

router.get("/", requireAuth, (req, res) => {
  return res.json({ files: listFiles(req.user.id) });
});

router.post("/decrypt", requireAuth, (req, res) => {
  try {
    const { vault_password, file_id } = req.body || {};
    if (!vault_password || !file_id) {
      return res.status(400).json({ detail: "vault_password and file_id are required" });
    }
    const { meta, plaintext } = decryptFromStore({ userId: req.user.id, vaultPassword: vault_password, fileId: file_id });

    logEvent({
      type: "FILE_DECRYPT",
      user_hash: sha256Hex(Buffer.from(String(req.user.id))),
      file_hash: meta.ciphertext_sha256_hex,
      success: true
    });

    return res.json({
      file_id: meta.id,
      filename: meta.filename,
      data_base64: plaintext.toString("base64")
    });
  } catch (e) {
    console.error(e);
    logEvent({
      type: e.code === "TAMPER" ? "FILE_TAMPER_DETECTED" : "FILE_DECRYPT",
      success: false,
      error: String(e.message || e)
    });
    return res.status(400).json({ detail: String(e.message || e) });
  }
});

module.exports = router;
