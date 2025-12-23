const express = require("express");

const messagingRoutes = require("./messaging/routes");
const fileRoutes = require("./files/routes");
const ledgerRoutes = require("./ledger/routes");

const { requireAuth } = require("../auth/middleware");
const { ensureUserKeys } = require("./keystore");
const { MerkleTree } = require("./core_crypto/merkle");
const { modExp } = require("./core_crypto/modexp");
const { caesarEncrypt, caesarBreak } = require("./core_crypto/caesar");

const router = express.Router();

// Ensure cryptographic keys exist for the authenticated user
router.use(requireAuth);
router.use((req, _res, next) => {
  ensureUserKeys(req.user.id);
  next();
});

router.use("/messages", messagingRoutes);
router.use("/files", fileRoutes);
router.use("/ledger", ledgerRoutes);

// --- Core crypto demo endpoints (useful for defense) ---
router.post("/core/merkle", (req, res) => {
  const { leaves } = req.body || {};
  if (!Array.isArray(leaves) || leaves.length === 0) {
    return res.status(400).json({ detail: "leaves must be a non-empty array" });
  }
  const tree = new MerkleTree(leaves.map(String));
  const root = tree.root().toString("hex");
  const proof = tree.getProof(0);
  const ok = MerkleTree.verifyProof(String(leaves[0]), 0, proof, root);
  return res.json({ root, sample_proof_for_first_leaf: proof, verify_first_leaf: ok });
});

router.get("/core/modexp", (req, res) => {
  const base = req.query.base ?? "7";
  const exp = req.query.exp ?? "123";
  const mod = req.query.mod ?? "2021";
  const result = modExp(base, exp, mod).toString();
  return res.json({ base, exp, mod, result });
});

router.post("/core/caesar", (req, res) => {
  const { text, shift } = req.body || {};
  if (text === undefined || shift === undefined) {
    return res.status(400).json({ detail: "text and shift are required" });
  }
  return res.json({ ciphertext: caesarEncrypt(text, Number(shift)) });
});

router.post("/core/caesar/break", (req, res) => {
  const { ciphertext } = req.body || {};
  if (!ciphertext) return res.status(400).json({ detail: "ciphertext is required" });
  return res.json({ candidates: caesarBreak(ciphertext) });
});

module.exports = router;
