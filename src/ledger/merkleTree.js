/**
 * AegisMCP - Cryptographic Binary Merkle Tree & Inclusion Proof Engine
 * Zero runtime dependencies (uses native node:crypto).
 * Implements RFC 6962 domain separation (0x00 for leaves, 0x01 for interior nodes)
 * to prevent second-preimage attacks.
 */

'use strict';

const crypto = require('node:crypto');

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Domain-separated leaf hashing: SHA256(0x00 || leafData)
 */
function hashLeaf(leafData) {
  const content = typeof leafData === 'string' ? leafData : JSON.stringify(leafData);
  return crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(content, 'utf8')])).digest('hex');
}

/**
 * Domain-separated node hashing: SHA256(0x01 || left || right)
 */
function hashNodes(leftHex, rightHex) {
  const leftBuf = Buffer.from(leftHex, 'hex');
  const rightBuf = Buffer.from(rightHex, 'hex');
  return crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), leftBuf, rightBuf])).digest('hex');
}

class MerkleTree {
  /**
   * @param {Array<string|Object>} leaves - Raw leaves or leaf hashes
   */
  constructor(leaves = []) {
    this.rawLeaves = leaves;
    this.leaves = leaves.map(l => (typeof l === 'string' && l.length === 64 && /^[0-9a-f]+$/i.test(l) ? l : hashLeaf(l)));
    this.layers = [];
    this._buildTree();
  }

  _buildTree() {
    if (this.leaves.length === 0) {
      this.layers = [[sha256('')]];
      return;
    }

    this.layers = [this.leaves];
    let current = this.leaves;

    while (current.length > 1) {
      const next = [];
      for (let i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          next.push(hashNodes(current[i], current[i + 1]));
        } else {
          // Odd element: carry forward or duplicate (RFC 6962 carries forward)
          next.push(current[i]);
        }
      }
      this.layers.push(next);
      current = next;
    }
  }

  getRoot() {
    if (this.layers.length === 0 || this.layers[this.layers.length - 1].length === 0) {
      return null;
    }
    return this.layers[this.layers.length - 1][0];
  }

  /**
   * Generates a cryptographic inclusion proof for a leaf at index
   * @param {number} leafIndex
   * @returns {{ leafIndex: number, leafHash: string, rootHash: string, proof: Array<{position: 'left'|'right', hash: string}> }}
   */
  getInclusionProof(leafIndex) {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`Leaf index ${leafIndex} out of bounds (total leaves: ${this.leaves.length})`);
    }

    const proof = [];
    let idx = leafIndex;

    for (let layerIdx = 0; layerIdx < this.layers.length - 1; layerIdx++) {
      const layer = this.layers[layerIdx];
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;

      if (siblingIdx < layer.length) {
        proof.push({
          position: isRight ? 'left' : 'right',
          hash: layer[siblingIdx]
        });
      }

      idx = Math.floor(idx / 2);
    }

    return {
      leafIndex,
      leafHash: this.leaves[leafIndex],
      rootHash: this.getRoot(),
      treeSize: this.leaves.length,
      proof
    };
  }

  /**
   * Static standalone method to verify an inclusion proof against a root hash
   * in constant time without needing the tree structure.
   */
  static verifyProof(leafHash, proof, rootHash) {
    if (!leafHash || !proof || !rootHash) return false;

    let currentHash = leafHash;

    for (const step of proof) {
      if (!step.hash || !step.position) return false;

      if (step.position === 'left') {
        currentHash = hashNodes(step.hash, currentHash);
      } else if (step.position === 'right') {
        currentHash = hashNodes(currentHash, step.hash);
      } else {
        return false;
      }
    }

    if (currentHash.length !== rootHash.length) return false;

    try {
      return crypto.timingSafeEqual(Buffer.from(currentHash, 'hex'), Buffer.from(rootHash, 'hex'));
    } catch (_) {
      return currentHash === rootHash;
    }
  }
}

module.exports = {
  MerkleTree,
  hashLeaf,
  hashNodes,
  sha256
};
