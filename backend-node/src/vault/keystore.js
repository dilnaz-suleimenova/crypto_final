const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const BASE_DIR = path.join(__dirname, "..", "..", "keys", "vault");

function ensureDir() {
  if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });
}

function userKeyPath(userId, name) {
  ensureDir();
  return path.join(BASE_DIR, `user_${userId}_${name}`);
}

function ensureUserKeys(userId) {
  // ECDH keys (raw) + Ed25519 signing keys (PEM)
  const ecdhPrivPath = userKeyPath(userId, "ecdh_priv.b64");
  const ecdhPubPath = userKeyPath(userId, "ecdh_pub.b64");
  if (!fs.existsSync(ecdhPrivPath) || !fs.existsSync(ecdhPubPath)) {
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();
    fs.writeFileSync(ecdhPrivPath, ecdh.getPrivateKey().toString("base64"));
    fs.writeFileSync(ecdhPubPath, ecdh.getPublicKey().toString("base64"));
  }

  const signPrivPath = userKeyPath(userId, "ed25519_priv.pem");
  const signPubPath = userKeyPath(userId, "ed25519_pub.pem");
  if (!fs.existsSync(signPrivPath) || !fs.existsSync(signPubPath)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    fs.writeFileSync(signPrivPath, privateKey.export({ type: "pkcs8", format: "pem" }));
    fs.writeFileSync(signPubPath, publicKey.export({ type: "spki", format: "pem" }));
  }

  return {
    ecdhPrivPath,
    ecdhPubPath,
    signPrivPath,
    signPubPath
  };
}

function getUserEcdhKeypair(userId) {
  const { ecdhPrivPath, ecdhPubPath } = ensureUserKeys(userId);
  return {
    privateKey: Buffer.from(fs.readFileSync(ecdhPrivPath, "utf8"), "base64"),
    publicKey: Buffer.from(fs.readFileSync(ecdhPubPath, "utf8"), "base64")
  };
}

function getUserSigningKeypair(userId) {
  const { signPrivPath, signPubPath } = ensureUserKeys(userId);
  return {
    privateKeyPem: fs.readFileSync(signPrivPath, "utf8"),
    publicKeyPem: fs.readFileSync(signPubPath, "utf8")
  };
}

module.exports = { ensureUserKeys, getUserEcdhKeypair, getUserSigningKeypair };
