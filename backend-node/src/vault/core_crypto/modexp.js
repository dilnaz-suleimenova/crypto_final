/**
 * Modular exponentiation (square-and-multiply) from scratch.
 * Computes (base^exp) mod mod efficiently.
 */
function modExp(base, exp, mod) {
  if (mod <= 0) throw new Error("mod must be positive");
  let b = BigInt(base) % BigInt(mod);
  let e = BigInt(exp);
  let m = BigInt(mod);
  let result = 1n;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

module.exports = { modExp };
