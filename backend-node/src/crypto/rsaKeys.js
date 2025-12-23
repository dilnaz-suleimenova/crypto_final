const fs = require("fs");
const crypto = require("crypto");
const { RSA_PRIVATE_KEY_PATH, RSA_PUBLIC_KEY_PATH, KEYS_DIR } = require("../config");

function ensureKeypair() {
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
  }
  if (!fs.existsSync(RSA_PRIVATE_KEY_PATH) || !fs.existsSync(RSA_PUBLIC_KEY_PATH)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" }
    });
    fs.writeFileSync(RSA_PRIVATE_KEY_PATH, privateKey, "utf8");
    fs.writeFileSync(RSA_PUBLIC_KEY_PATH, publicKey, "utf8");
  }
}

function loadPrivateKey() {
  ensureKeypair();
  return fs.readFileSync(RSA_PRIVATE_KEY_PATH, "utf8");
}

function loadPublicKey() {
  ensureKeypair();
  return fs.readFileSync(RSA_PUBLIC_KEY_PATH, "utf8");
}

function signData(data) {
  const privateKey = loadPrivateKey();
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(data);
  sign.end();
  return sign.sign(privateKey);
}

function verifySignature(data, signature) {
  const publicKey = loadPublicKey();
  const verify = crypto.createVerify("RSA-SHA256");
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature);
}

module.exports = { ensureKeypair, loadPrivateKey, loadPublicKey, signData, verifySignature };
