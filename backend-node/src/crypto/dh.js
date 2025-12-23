const crypto = require("crypto");

function generateDhPair() {
  const dh = crypto.createDiffieHellman(2048);
  const publicKey = dh.generateKeys();
  const privateKey = dh; // object
  return { privateKey, publicKey };
}

function computeSharedSecret(privateDh, peerPublicKey) {
  return privateDh.computeSecret(peerPublicKey);
}

module.exports = { generateDhPair, computeSharedSecret };
