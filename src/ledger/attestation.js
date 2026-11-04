/**
 * AegisMCP - Cryptographic HMAC-SHA256 Attestation Signatures
 *
 * Provides cryptographic attestation capabilities for operators to sign and verify
 * audit blocks and ledger checkpoints using secret keys:
 *   HMAC-SHA256(secret, block.hash)
 *
 * Implements:
 * 1. attestBlock(block, secretKey): Computes cryptographic HMAC-SHA256 signature for a block.
 * 2. verifyAttestation(block, secretKey, signature): Constant-time cryptographic verification.
 * 3. recordAttestationCheckpoint(ledger, secretKey, options): Seals attestation checkpoints
 *    directly into the ledger as ATTESTATION_CHECKPOINT events.
 * 4. verifyAttestationCheckpoint(ledger, checkpointBlock, secretKey): End-to-end verification.
 * 5. verifyAllAttestations(ledger, secretKey): Full-chain attestation sweep.
 * 6. LedgerAttestor class: High-level operator attestation manager.
 */

'use strict';

const crypto = require('node:crypto');
const { AuditBlock } = require('./auditLedger');

const ATTESTATION_EVENT_TYPE = 'ATTESTATION_CHECKPOINT';

/**
 * Extracts and validates the 64-character SHA-256 hash string from a block or hash string.
 * @param {Object|string} block
 * @returns {string} 64-char hex hash
 */
function extractBlockHash(block) {
  if (!block) {
    throw new TypeError('Invalid block: block must not be null or undefined');
  }

  let hash = null;
  if (typeof block === 'string') {
    hash = block;
  } else if (typeof block === 'object' && typeof block.hash === 'string') {
    hash = block.hash;
  }

  if (!hash || typeof hash !== 'string' || hash.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(hash)) {
    throw new TypeError('Invalid block: must contain a valid 64-character SHA-256 hex hash');
  }

  return hash.toLowerCase();
}

/**
 * Computes an HMAC-SHA256 attestation signature for an AuditBlock or block hash using an operator secret key.
 * Signature formula: HMAC-SHA256(secretKey, block.hash)
 *
 * @param {AuditBlock|Object|string} block - AuditBlock instance or object with .hash
 * @param {string|Buffer} secretKey - Operator cryptographic secret key
 * @returns {string} 64-character hex-encoded HMAC-SHA256 signature
 */
function attestBlock(block, secretKey) {
  if (!secretKey || (typeof secretKey !== 'string' && !Buffer.isBuffer(secretKey))) {
    throw new TypeError('Invalid secretKey: must be a non-empty string or Buffer');
  }

  if (typeof secretKey === 'string' && secretKey.length === 0) {
    throw new TypeError('Invalid secretKey: must be a non-empty string');
  }

  const hash = extractBlockHash(block);
  return crypto.createHmac('sha256', secretKey).update(hash, 'utf8').digest('hex');
}

/**
 * Verifies an HMAC-SHA256 attestation signature against an AuditBlock in constant time.
 *
 * @param {AuditBlock|Object|string} block - AuditBlock instance or object with .hash
 * @param {string|Buffer} secretKey - Operator cryptographic secret key
 * @param {string|Object} signature - Signature hex string or attestation object with .signature
 * @returns {boolean} True if signature is cryptographically valid, false otherwise
 */
function verifyAttestation(block, secretKey, signature) {
  if (!secretKey || (typeof secretKey !== 'string' && !Buffer.isBuffer(secretKey))) {
    return false;
  }

  let rawSignature = signature;
  if (typeof signature === 'object' && signature !== null && typeof signature.signature === 'string') {
    rawSignature = signature.signature;
  }

  if (
    !rawSignature ||
    typeof rawSignature !== 'string' ||
    rawSignature.length !== 64 ||
    !/^[0-9a-fA-F]{64}$/.test(rawSignature)
  ) {
    return false;
  }

  let expectedSignature;
  try {
    expectedSignature = attestBlock(block, secretKey);
  } catch {
    return false;
  }

  const sigBuffer = Buffer.from(rawSignature.toLowerCase(), 'hex');
  const expBuffer = Buffer.from(expectedSignature.toLowerCase(), 'hex');

  if (sigBuffer.length !== expBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(sigBuffer, expBuffer);
}

/**
 * Attests a block and records an ATTESTATION_CHECKPOINT event directly into the ledger chain.
 *
 * @param {AuditLedger} ledger - Active AuditLedger instance
 * @param {string|Buffer} secretKey - Operator secret key
 * @param {Object} [options]
 * @param {AuditBlock|number} [options.block] - Specific block or block index to attest (defaults to latest)
 * @param {string} [options.operatorId='operator-root'] - ID or name of signing operator
 * @param {string} [options.checkpointType='PERIODIC'] - E.g. 'PERIODIC', 'COMPLIANCE', 'DEPLOYMENT'
 * @param {string} [options.notes] - Descriptive notes
 * @param {Object} [options.extra] - Additional metadata for the checkpoint
 * @returns {AuditBlock} The newly appended checkpoint block in the ledger
 */
function recordAttestationCheckpoint(ledger, secretKey, options = {}) {
  if (!ledger || typeof ledger.append !== 'function' || typeof ledger.getLatestBlock !== 'function') {
    throw new TypeError('Invalid ledger: must be an instance of AuditLedger');
  }

  if (!secretKey) {
    throw new TypeError('Invalid secretKey: secret key is required for attestation');
  }

  let targetBlock = null;
  if (options.block && typeof options.block === 'object') {
    targetBlock = options.block;
  } else if (typeof options.blockIndex === 'number') {
    const fullChain = ledger.getFullChain();
    targetBlock = fullChain.find(b => b.index === options.blockIndex);
    if (!targetBlock) {
      throw new Error(`Target block #${options.blockIndex} not found in ledger`);
    }
  } else {
    targetBlock = ledger.getLatestBlock();
  }

  if (!targetBlock || !targetBlock.hash) {
    throw new Error('Cannot attest empty ledger or block with missing hash');
  }

  const signature = attestBlock(targetBlock, secretKey);
  const operatorId = options.operatorId || options.operator || 'operator-root';
  const checkpointTimestamp = options.timestamp || new Date().toISOString();

  const checkpointEvent = {
    targetBlockIndex: targetBlock.index,
    targetBlockHash: targetBlock.hash,
    signature,
    operatorId,
    checkpointTimestamp,
    checkpointType: options.checkpointType || 'PERIODIC',
    notes: options.notes || 'HMAC-SHA256 Cryptographic Attestation Checkpoint',
    ...(options.extra || {})
  };

  const checkpointBlock = ledger.append(ATTESTATION_EVENT_TYPE, checkpointEvent);
  return checkpointBlock;
}

/**
 * Cryptographically verifies an ATTESTATION_CHECKPOINT block against the referenced block in the ledger.
 *
 * @param {AuditLedger} ledger - The ledger containing the chain
 * @param {AuditBlock} checkpointBlock - The block containing the ATTESTATION_CHECKPOINT event
 * @param {string|Buffer} secretKey - The operator secret key to verify against
 * @returns {{ valid: boolean, error?: string, targetBlock?: AuditBlock, checkpointBlock?: AuditBlock, operatorId?: string }}
 */
function verifyAttestationCheckpoint(ledger, checkpointBlock, secretKey) {
  if (!checkpointBlock || !checkpointBlock.event) {
    return { valid: false, error: 'Invalid checkpoint block' };
  }

  const evt = checkpointBlock.event;
  if (evt.type !== ATTESTATION_EVENT_TYPE) {
    return { valid: false, error: `Block event type is not ${ATTESTATION_EVENT_TYPE}` };
  }

  const fullChain = ledger.getFullChain();
  const targetIndex = evt.targetBlockIndex;
  const targetBlock = fullChain.find(b => b.index === targetIndex);

  if (!targetBlock) {
    return {
      valid: false,
      error: `Target block #${targetIndex} not found in ledger chain`,
      targetIndex
    };
  }

  if (targetBlock.hash !== evt.targetBlockHash) {
    return {
      valid: false,
      error: `Target block hash mismatch: block has ${targetBlock.hash}, checkpoint recorded ${evt.targetBlockHash}`,
      targetIndex,
      expectedHash: evt.targetBlockHash,
      actualHash: targetBlock.hash
    };
  }

  // Verify that the target block's event data has not been modified (tamper detection)
  const computedTargetHash = AuditBlock.calculateHash(
    targetBlock.index,
    targetBlock.timestamp,
    targetBlock.prevHash,
    targetBlock.event
  );
  if (computedTargetHash !== targetBlock.hash) {
    return {
      valid: false,
      error: `Target block #${targetIndex} internal hash mismatch: payload tampering detected`,
      targetIndex,
      expectedHash: computedTargetHash,
      actualHash: targetBlock.hash
    };
  }

  const isSigValid = verifyAttestation(targetBlock, secretKey, evt.signature);
  if (!isSigValid) {
    return {
      valid: false,
      error: 'HMAC-SHA256 signature verification failed for target block',
      targetIndex,
      targetBlockHash: targetBlock.hash,
      signature: evt.signature
    };
  }

  return {
    valid: true,
    targetBlock,
    checkpointBlock,
    operatorId: evt.operatorId,
    timestamp: evt.checkpointTimestamp
  };
}

/**
 * Scans the entire ledger chain for all ATTESTATION_CHECKPOINT events and cryptographically verifies each one.
 *
 * @param {AuditLedger} ledger
 * @param {string|Buffer} secretKey
 * @returns {{ valid: boolean, checkpointCount: number, verifiedCount: number, failures: Array<Object> }}
 */
function verifyAllAttestations(ledger, secretKey) {
  if (!ledger || typeof ledger.getFullChain !== 'function') {
    throw new TypeError('Invalid ledger: must be an instance of AuditLedger');
  }

  const fullChain = ledger.getFullChain();
  const checkpoints = fullChain.filter(b => b.event && b.event.type === ATTESTATION_EVENT_TYPE);
  const failures = [];
  let verifiedCount = 0;

  for (const cp of checkpoints) {
    const res = verifyAttestationCheckpoint(ledger, cp, secretKey);
    if (res.valid) {
      verifiedCount++;
    } else {
      failures.push({
        checkpointIndex: cp.index,
        targetBlockIndex: cp.event.targetBlockIndex,
        error: res.error
      });
    }
  }

  return {
    valid: failures.length === 0,
    checkpointCount: checkpoints.length,
    verifiedCount,
    failures
  };
}

/**
 * Class representing an operator attestation manager.
 */
class LedgerAttestor {
  constructor(secretKey, options = {}) {
    if (!secretKey) {
      throw new TypeError('Secret key is required for LedgerAttestor');
    }
    this.secretKey = secretKey;
    this.operatorId = options.operatorId || 'operator-root';
  }

  attest(block) {
    return attestBlock(block, this.secretKey);
  }

  verify(block, signature) {
    return verifyAttestation(block, this.secretKey, signature);
  }

  checkpoint(ledger, options = {}) {
    return recordAttestationCheckpoint(ledger, this.secretKey, {
      operatorId: this.operatorId,
      ...options
    });
  }

  verifyCheckpoint(ledger, checkpointBlock) {
    return verifyAttestationCheckpoint(ledger, checkpointBlock, this.secretKey);
  }

  verifyAll(ledger) {
    return verifyAllAttestations(ledger, this.secretKey);
  }
}

module.exports = {
  ATTESTATION_EVENT_TYPE,
  attestBlock,
  verifyAttestation,
  recordAttestationCheckpoint,
  createAttestationCheckpoint: recordAttestationCheckpoint,
  verifyAttestationCheckpoint,
  verifyAllAttestations,
  LedgerAttestor
};
