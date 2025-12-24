const express = require("express");
const { requireAuth } = require("../../auth/middleware");
const { getState, minePending, validateChain } = require("./blockchain");

const router = express.Router();

router.get("/", requireAuth, (req, res) => {
  const state = getState();
  return res.json({ chain: state.chain, pending: state.pending });
});

router.post("/mine", requireAuth, (req, res) => {
  const state = minePending();
  return res.json(state);
});

router.get("/validate", requireAuth, (req, res) => {
  return res.json(validateChain());
});

module.exports = router;
