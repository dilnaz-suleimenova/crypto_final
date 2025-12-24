const { sha256 } = require("./hash");

/**
 * Minimal Merkle tree implementation (from scratch) with proof generation.
 * Leaves are hashed with SHA-256; internal nodes hash(left||right).
 */
class MerkleTree {
  constructor(leaves) {
    this.leaves = (leaves || []).map((x) => Buffer.isBuffer(x) ? x : Buffer.from(String(x)));
    this.levels = [];
    this._build();
  }

  _build() {
    const leafHashes = this.leaves.map((l) => sha256(l));
    this.levels = [leafHashes];
    let level = leafHashes;
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = (i + 1 < level.length) ? level[i + 1] : level[i]; // duplicate if odd
        next.push(sha256(Buffer.concat([left, right])));
      }
      this.levels.push(next);
      level = next;
    }
  }

  root() {
    if (this.levels.length === 0 || this.levels[0].length === 0) return Buffer.alloc(32, 0);
    return this.levels[this.levels.length - 1][0];
  }

  /**
   * Returns Merkle proof for a leaf index.
   * Proof is an array of objects: { sibling: <hex>, isLeftSibling: boolean }
   */
  getProof(index) {
    if (index < 0 || index >= this.leaves.length) throw new Error("Invalid leaf index");
    const proof = [];
    let idx = index;
    for (let level = 0; level < this.levels.length - 1; level++) {
      const nodes = this.levels[level];
      const isRightNode = (idx % 2 === 1);
      const siblingIdx = isRightNode ? idx - 1 : idx + 1;
      const sibling = (siblingIdx < nodes.length) ? nodes[siblingIdx] : nodes[idx];
      proof.push({ sibling: sibling.toString("hex"), isLeftSibling: isRightNode });
      idx = Math.floor(idx / 2);
    }
    return proof;
  }

  static verifyProof(leaf, index, proof, expectedRootHex) {
    let hash = sha256(Buffer.isBuffer(leaf) ? leaf : Buffer.from(String(leaf)));
    let idx = index;
    for (const step of proof) {
      const sibling = Buffer.from(step.sibling, "hex");
      const isRightNode = (idx % 2 === 1);
      // step.isLeftSibling tells us sibling is left if current is right
      const left = isRightNode ? sibling : hash;
      const right = isRightNode ? hash : sibling;
      hash = sha256(Buffer.concat([left, right]));
      idx = Math.floor(idx / 2);
    }
    return hash.toString("hex") === expectedRootHex;
  }
}

module.exports = { MerkleTree };
