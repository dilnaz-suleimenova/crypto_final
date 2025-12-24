const ALPHABET = "abcdefghijklmnopqrstuvwxyz";

function caesarEncrypt(text, shift) {
  const s = ((shift % 26) + 26) % 26;
  return String(text).split("").map(ch => {
    const lower = ch.toLowerCase();
    const idx = ALPHABET.indexOf(lower);
    if (idx === -1) return ch;
    const out = ALPHABET[(idx + s) % 26];
    return ch === lower ? out : out.toUpperCase();
  }).join("");
}

function caesarDecrypt(ciphertext, shift) {
  return caesarEncrypt(ciphertext, -shift);
}

// Simple brute-force breaker (returns candidates)
function caesarBreak(ciphertext) {
  const candidates = [];
  for (let s = 0; s < 26; s++) {
    candidates.push({ shift: s, plaintext: caesarDecrypt(ciphertext, s) });
  }
  return candidates;
}

module.exports = { caesarEncrypt, caesarDecrypt, caesarBreak };
