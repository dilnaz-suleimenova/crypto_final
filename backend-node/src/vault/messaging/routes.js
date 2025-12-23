const express = require("express");
const { requireAuth } = require("../../auth/middleware");
const { sendMessage, inbox, readAndDecrypt } = require("./service");
const { logEvent } = require("../ledger/blockchain");
const { sha256Hex } = require("../core_crypto/hash");

const router = express.Router();

router.post("/send", requireAuth, (req, res) => {
  try {
    const senderId = req.user.id;
    const { recipient_id, message } = req.body || {};
    if (!recipient_id || message === undefined) {
      return res.status(400).json({ detail: "recipient_id and message are required" });
    }
    const record = sendMessage({ senderId, recipientId: Number(recipient_id), message });

    logEvent({
      type: "MSG_SEND",
      user_hash: sha256Hex(Buffer.from(String(senderId))),
      recipient_hash: sha256Hex(Buffer.from(String(recipient_id))),
      msg_hash: record.ciphertext_hash,
      success: true
    });

    return res.json({ id: record.id, created_at: record.created_at });
  } catch (e) {
    console.error(e);
    logEvent({ type: "MSG_SEND", success: false, error: String(e.message || e) });
    return res.status(500).json({ detail: "Failed to send message" });
  }
});

router.get("/inbox", requireAuth, (req, res) => {
  const msgs = inbox(req.user.id).map(m => ({
    id: m.id,
    sender_id: m.sender_id,
    recipient_id: m.recipient_id,
    created_at: m.created_at,
    ciphertext_hash: m.ciphertext_hash
  }));
  return res.json({ messages: msgs });
});

router.get("/:id", requireAuth, (req, res) => {
  try {
    const out = readAndDecrypt({ userId: req.user.id, messageId: req.params.id });
    return res.json({
      id: out.id,
      sender_id: out.sender_id,
      recipient_id: out.recipient_id,
      created_at: out.created_at,
      signature_ok: out.signature_ok,
      plaintext: out.plaintext
    });
  } catch (e) {
    return res.status(400).json({ detail: String(e.message || e) });
  }
});

module.exports = router;
