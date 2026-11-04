/**
 * AegisMCP - Tamper-Evident Hash-Chained Audit Ledger
 * Cryptographic Merkle-linked audit trail for AI tool invocations and security events.
 */

'use strict';

const crypto = require('node:crypto');

const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/**
 * Deterministically serializes an object for canonical hashing
 */
function canonicalStringify(obj, visited = new Set()) {
  if (obj === undefined) {
    return 'null';
  }
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (visited.has(obj)) {
    return '"[CIRCULAR]"';
  }
  visited.add(obj);

  if (Array.isArray(obj)) {
    const res = '[' + obj.map(item => canonicalStringify(item, visited)).join(',') + ']';
    visited.delete(obj);
    return res;
  }
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  const res = '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k], visited)).join(',') + '}';
  visited.delete(obj);
  return res;
}

class AuditBlock {
  constructor(index, timestamp, prevHash, event, hash = null) {
    this.index = index;
    this.timestamp = timestamp;
    this.prevHash = prevHash;
    this.event = event;
    this.hash = hash || AuditBlock.calculateHash(index, timestamp, prevHash, event);
  }

  static calculateHash(index, timestamp, prevHash, event) {
    const canonicalEvent = canonicalStringify(event);
    const raw = `${index}|${timestamp}|${prevHash}|${canonicalEvent}`;
    return sha256(raw);
  }
}

class AuditLedger {
  constructor(options = {}) {
    this.maxMemoryBlocks = options.maxMemoryBlocks || 5000;
    this.chain = [];
    this.archivedBlocks = [];
    this.initGenesisBlock();
  }

  initGenesisBlock() {
    const timestamp = '2026-11-04T00:00:00.000Z';
    const genesisEvent = {
      type: 'GENESIS',
      description: 'AegisMCP Cryptographic Audit Ledger Initialized',
      version: '1.0.0',
      system: 'Aegis Security Engine'
    };
    const genesisBlock = new AuditBlock(0, timestamp, GENESIS_PREV_HASH, genesisEvent);
    this.chain.push(genesisBlock);
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  getFullChain() {
    return [...this.archivedBlocks, ...this.chain];
  }

  /**
   * Appends an audit event to the tamper-evident chain.
   */
  append(type, data = {}) {
    const latest = this.getLatestBlock();
    const index = latest.index + 1;
    const timestamp = new Date().toISOString();
    const prevHash = latest.hash;

    const event = {
      type,
      ...data
    };

    const block = new AuditBlock(index, timestamp, prevHash, event);
    this.chain.push(block);

    if (this.chain.length > this.maxMemoryBlocks) {
      const pruned = this.chain.shift();
      this.archivedBlocks.push(pruned);
    }

    return block;
  }

  /**
   * Cryptographically verifies the integrity of the entire ledger chain.
   */
  verify() {
    const fullChain = this.getFullChain();
    if (fullChain.length === 0) {
      return { valid: false, error: 'Ledger is empty (missing genesis block)' };
    }

    // Verify genesis block
    const genesis = fullChain[0];
    if (genesis.index !== 0 || genesis.prevHash !== GENESIS_PREV_HASH) {
      return {
        valid: false,
        error: 'Corrupted genesis block',
        brokenIndex: 0
      };
    }
    const computedGenesisHash = AuditBlock.calculateHash(
      genesis.index,
      genesis.timestamp,
      genesis.prevHash,
      genesis.event
    );
    if (genesis.hash !== computedGenesisHash) {
      return {
        valid: false,
        error: 'Genesis block hash does not match computed hash',
        brokenIndex: 0,
        expectedHash: computedGenesisHash,
        actualHash: genesis.hash
      };
    }

    // Verify sequential links across entire continuous chain
    for (let i = 1; i < fullChain.length; i++) {
      const current = fullChain[i];
      const prev = fullChain[i - 1];

      // Check index sequence
      if (current.index !== prev.index + 1) {
        return {
          valid: false,
          error: `Broken index sequence at block #${current.index}: expected ${prev.index + 1}`,
          brokenIndex: current.index
        };
      }

      // Check previous hash pointer
      if (current.prevHash !== prev.hash) {
        return {
          valid: false,
          error: `Hash pointer mismatch at block #${current.index}: does not match prev block hash`,
          brokenIndex: current.index,
          expectedPrevHash: prev.hash,
          actualPrevHash: current.prevHash
        };
      }

      // Recompute and check current block hash
      const computedHash = AuditBlock.calculateHash(
        current.index,
        current.timestamp,
        current.prevHash,
        current.event
      );
      if (current.hash !== computedHash) {
        return {
          valid: false,
          error: `Cryptographic tampering detected! Block #${current.index} hash corrupted`,
          brokenIndex: current.index,
          expectedHash: computedHash,
          actualHash: current.hash
        };
      }
    }

    return {
      valid: true,
      blockCount: fullChain.length,
      activeBlocks: this.chain.length,
      archivedBlocks: this.archivedBlocks.length,
      headHash: this.getLatestBlock().hash,
      genesisHash: genesis.hash,
      verifiedAt: new Date().toISOString()
    };
  }

  /**
   * For testing and security demonstrations: simulates an adversary tampering with a block's event data.
   */
  tamper(index, modifiedEvent) {
    const fullChain = this.getFullChain();
    const block = fullChain.find(b => b.index === index);
    if (!block) {
      throw new Error(`Block #${index} not found in chain`);
    }
    block.event = modifiedEvent;
    // Note: block.hash is intentionally NOT updated, simulating undetected payload modification
    return block;
  }

  /**
   * Exports an audit proof for external verification.
   */
  exportProof() {
    const fullChain = this.getFullChain();
    const verification = this.verify();
    return {
      proofVersion: '1.0',
      timestamp: new Date().toISOString(),
      integrityStatus: verification.valid ? 'VERIFIED_PRISTINE' : 'COMPROMISED',
      blockCount: fullChain.length,
      headHash: this.getLatestBlock().hash,
      genesisHash: fullChain[0].hash,
      blocks: fullChain.map(b => ({
        index: b.index,
        timestamp: b.timestamp,
        prevHash: b.prevHash,
        hash: b.hash,
        eventType: b.event.type,
        eventSummary: b.event.tool || b.event.description || b.event.signature || 'EVENT'
      }))
    };
  }

  getRecentBlocks(limit = 20) {
    return this.chain.slice(-limit).reverse();
  }
}

module.exports = {
  AuditBlock,
  AuditLedger,
  sha256,
  canonicalStringify
};
