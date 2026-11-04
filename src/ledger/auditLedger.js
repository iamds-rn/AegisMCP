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
    this.tamperBackup = new Map();
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
      verifiedBlocks: fullChain.length,
      brokenBlockIndex: -1,
      brokenIndex: -1,
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
    if (!this.tamperBackup.has(index)) {
      this.tamperBackup.set(index, JSON.parse(JSON.stringify(block.event)));
    }
    block.event = modifiedEvent;
    // Note: block.hash is intentionally NOT updated, simulating undetected payload modification
    return block;
  }

  /**
   * Restores a tampered block back to its canonical pristine payload.
   */
  restoreChain(index) {
    if (!this.tamperBackup.has(index)) {
      return false;
    }
    const fullChain = this.getFullChain();
    const block = fullChain.find(b => b.index === index);
    if (!block) return false;
    block.event = this.tamperBackup.get(index);
    this.tamperBackup.delete(index);
    return true;
  }

  /**
   * Restores all tampered blocks to pristine state and re-verifies.
   */
  restoreAll() {
    let restoredCount = 0;
    for (const [index, originalEvent] of this.tamperBackup.entries()) {
      const fullChain = this.getFullChain();
      const block = fullChain.find(b => b.index === index);
      if (block) {
        block.event = originalEvent;
        restoredCount++;
      }
    }
    this.tamperBackup.clear();
    return {
      restoredCount,
      verification: this.verify()
    };
  }

  /**
   * Deep cryptographic forensics: pinpoints exact tamper locus, diffs altered data,
   * and computes downstream invalidation cascade blast radius.
   */
  locateTamper() {
    const fullChain = this.getFullChain();
    const verification = this.verify();

    if (verification.valid) {
      return {
        intact: true,
        blockCount: fullChain.length,
        headHash: this.getLatestBlock().hash,
        genesisHash: fullChain[0].hash,
        forensicSummary: `Audit Ledger is cryptographically PRISTINE. All ${fullChain.length} blocks verified against SHA-256 Merkle chain.`
      };
    }

    if (fullChain.length === 0) {
      return {
        intact: false,
        tamperedIndex: -1,
        brokenBlock: null,
        expectedHash: undefined,
        actualHash: undefined,
        expectedPrevHash: undefined,
        actualPrevHash: undefined,
        errorMessage: verification.error || 'Ledger is empty (missing genesis block)',
        cascadeBlastRadius: 0,
        invalidatedIndices: [],
        fieldDiff: null,
        forensicSummary: 'CRITICAL INTEGRITY BREACH: Ledger chain is empty (genesis block missing).'
      };
    }

    const brokenIndex = verification.brokenIndex !== undefined ? verification.brokenIndex : -1;
    const brokenBlock = brokenIndex >= 0 ? (fullChain.find(b => b.index === brokenIndex) || null) : null;
    const originalEvent = brokenIndex >= 0 ? this.tamperBackup.get(brokenIndex) : null;

    // Calculate downstream cascade safely
    const blastRadiusCount = brokenIndex >= 0 ? Math.max(0, fullChain.length - brokenIndex) : 0;
    const invalidatedIndices = [];
    if (brokenIndex >= 0) {
      for (let i = brokenIndex; i < fullChain.length; i++) {
        invalidatedIndices.push(i);
      }
    }

    // Compute field-level diff if pristine snapshot exists
    let fieldDiff = null;
    if (originalEvent && brokenBlock) {
      fieldDiff = {
        pristine: originalEvent,
        tampered: brokenBlock.event,
        changedKeys: []
      };
      const allKeys = new Set([...Object.keys(originalEvent), ...Object.keys(brokenBlock.event)]);
      for (const k of allKeys) {
        if (JSON.stringify(originalEvent[k]) !== JSON.stringify(brokenBlock.event[k])) {
          fieldDiff.changedKeys.push({
            key: k,
            expected: originalEvent[k],
            observed: brokenBlock.event[k]
          });
        }
      }
    }

    const errorDesc = verification.error || 'Cryptographic verification failure';
    const forensicSummary = brokenIndex >= 0
      ? `CRITICAL INTEGRITY BREACH: Tampering localized at block #${brokenIndex}. Integrity failure: ${errorDesc}. Invalidation blast radius spans ${blastRadiusCount} downstream block(s) [indices: ${invalidatedIndices.slice(0, 5).join(', ')}${invalidatedIndices.length > 5 ? '...' : ''}].`
      : `CRITICAL INTEGRITY BREACH: Chain invalid: ${errorDesc}.`;

    return {
      intact: false,
      tamperedIndex: brokenIndex,
      brokenBlock,
      expectedHash: verification.expectedHash,
      actualHash: verification.actualHash,
      expectedPrevHash: verification.expectedPrevHash,
      actualPrevHash: verification.actualPrevHash,
      errorMessage: verification.error,
      cascadeBlastRadius: blastRadiusCount,
      invalidatedIndices,
      fieldDiff,
      forensicSummary
    };
  }

  /**
   * Time-Travel Inspector: Reconstructs state metrics as they existed at a historical block index.
   */
  getSnapshotAtBlock(targetIndex) {
    const fullChain = this.getFullChain();
    if (targetIndex < 0 || targetIndex >= fullChain.length) {
      throw new Error(`Block index ${targetIndex} is out of bounds (0 to ${fullChain.length - 1}).`);
    }

    const targetBlock = fullChain[targetIndex];
    const eventCounts = {};
    const toolsCalled = new Set();
    const firewallBlocks = [];

    for (let i = 0; i <= targetIndex; i++) {
      const b = fullChain[i];
      const type = b.event.type || 'UNKNOWN';
      eventCounts[type] = (eventCounts[type] || 0) + 1;

      if (b.event.tool) {
        toolsCalled.add(b.event.tool);
      }
      if (type === 'FIREWALL_BLOCK') {
        firewallBlocks.push({
          blockIndex: b.index,
          timestamp: b.timestamp,
          ruleId: b.event.ruleId,
          signature: b.event.signature
        });
      }
    }

    return {
      targetIndex,
      timestamp: targetBlock.timestamp,
      hash: targetBlock.hash,
      prevHash: targetBlock.prevHash,
      event: targetBlock.event,
      historicalMetrics: {
        totalBlocksAtPoint: targetIndex + 1,
        eventCounts,
        uniqueToolsCalled: Array.from(toolsCalled),
        firewallBlockCount: firewallBlocks.length,
        recentFirewallBlocks: firewallBlocks.slice(-5)
      }
    };
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
