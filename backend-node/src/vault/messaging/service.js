const crypto = require("crypto");
const { readMessages, writeMessages } = require("./storage");
const { getUserEcdhKeypair, getUserSigningKeypair, ensureUserKeys } = require("../keystore");
const { hkdfSha256, aes256gcmEncrypt, aes256gcmDecrypt } = require("./crypto");
const { sha256Hex } = require("../core_crypto/hash");

function deriveMessageKey(sharedSecret, salt, info) {
  return hkdfSha256(sharedSecret, salt, Buffer.from(info), 32);
}

function signEd25519(privateKeyPem, data) {
  return crypto.sign(null, data, privateKeyPem);
}

function verifyEd25519(publicKeyPem, data, signature) {
  return crypto.verify(null, data, publicKeyPem, signature);
}

function sendMessage({ senderId, recipientId, message }) {
  ensureUserKeys(senderId);
  ensureUserKeys(recipientId);

  // 1) Ephemeral ECDH per message (session-like)
  const senderEph = crypto.createECDH("prime256v1");
  senderEph.generateKeys();
  const senderEphPub = senderEph.getPublicKey();

  // 2) Derive shared secret using recipient static ECDH pubkey
  const recipientEcdh = getUserEcdhKeypair(recipientId);
  const sharedSecret = senderEph.computeSecret(recipientEcdh.publicKey);

  // 3) HKDF
  const salt = crypto.randomBytes(16);
  const encKey = deriveMessageKey(sharedSecret, salt, "cryptovault_message_key");

  // 4) Encrypt message (AES-256-GCM)
  const plaintext = Buffer.from(String(message), "utf8");
  const aad = Buffer.from(JSON.stringify({ senderId, recipientId }), "utf8");
  const { nonce, ciphertext, tag } = aes256gcmEncrypt(encKey, plaintext, aad);

  // 5) Sign (ciphertext + nonce + tag + ephPub + salt)
  const { privateKeyPem: signPriv } = getUserSigningKeypair(senderId);
  const signedBlob = Buffer.concat([salt, senderEphPub, nonce, tag, ciphertext]);
  const signature = signEd25519(signPriv, crypto.createHash("sha256").update(signedBlob).digest());

  // Store message
  const db = readMessages();
  const id = db.next_id++;
  const record = {
    id,
    sender_id: senderId,
    recipient_id: recipientId,
    created_at: new Date().toISOString(),
    salt_b64: salt.toString("base64"),
    sender_eph_pub_b64: senderEphPub.toString("base64"),
    nonce_b64: nonce.toString("base64"),
    tag_b64: tag.toString("base64"),
    ciphertext_b64: ciphertext.toString("base64"),
    signature_b64: signature.toString("base64"),
    // helpful for demo/debug
    ciphertext_hash: sha256Hex(ciphertext)
  };
  db.messages.push(record);
  writeMessages(db);
  return record;
}

function inbox(userId) {
  const db = readMessages();
  return db.messages.filter(m => m.recipient_id === userId || m.sender_id === userId);
}

function readAndDecrypt({ userId, messageId }) {
  const db = readMessages();
  const msg = db.messages.find(m => m.id === Number(messageId));
  if (!msg) throw new Error("Message not found");
  if (msg.recipient_id !== userId && msg.sender_id !== userId) throw new Error("Forbidden");

  ensureUserKeys(msg.sender_id);
  ensureUserKeys(msg.recipient_id);

  const salt = Buffer.from(msg.salt_b64, "base64");
  const senderEphPub = Buffer.from(msg.sender_eph_pub_b64, "base64");
  const nonce = Buffer.from(msg.nonce_b64, "base64");
  const tag = Buffer.from(msg.tag_b64, "base64");
  const ciphertext = Buffer.from(msg.ciphertext_b64, "base64");
  const signature = Buffer.from(msg.signature_b64, "base64");

  // Verify sender signature (non-repudiation)
  const { publicKeyPem: senderSignPub } = getUserSigningKeypair(msg.sender_id);
  const signedBlob = Buffer.concat([salt, senderEphPub, nonce, tag, ciphertext]);
  const digest = crypto.createHash("sha256").update(signedBlob).digest();
  const sigOk = verifyEd25519(senderSignPub, digest, signature);
  if (!sigOk) throw new Error("Invalid signature");

  // Recipient decrypts using their static ECDH private key (or sender if you want to show both)
  const decryptAsUser = userId === msg.recipient_id ? msg.recipient_id : msg.sender_id;
  const ecdhKeys = getUserEcdhKeypair(decryptAsUser);
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(ecdhKeys.privateKey);
  const sharedSecret = ecdh.computeSecret(senderEphPub);
  const encKey = deriveMessageKey(sharedSecret, salt, "cryptovault_message_key");
  const aad = Buffer.from(JSON.stringify({ senderId: msg.sender_id, recipientId: msg.recipient_id }), "utf8");

  const plaintext = aes256gcmDecrypt(encKey, nonce, ciphertext, tag, aad);
  return {
    ...msg,
    signature_ok: true,
    plaintext: plaintext.toString("utf8")
  };
}

module.exports = { sendMessage, inbox, readAndDecrypt };
