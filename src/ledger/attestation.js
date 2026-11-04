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
 * Also verifies internal cryptographic integrity if block fields are present.
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
    // If the object is an AuditBlock or contains full block fields, verify internal payload integrity
    if (
      block.event !== undefined &&
      typeof block.index === 'number' &&
      typeof block.timestamp === 'string' &&
      typeof block.prevHash === 'string'
    ) {
      const computed = AuditBlock.calculateHash(block.index, block.timestamp, block.prevHash, block.event);
      if (computed !== block.hash) {
        throw new Error(
          `Cannot attest tampered block #${block.index}: internal hash mismatch (computed ${computed} != recorded ${block.hash})`
        );
      }
    }
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

  if (Buffer.isBuffer(secretKey) && secretKey.length === 0) {
    throw new TypeError('Invalid secretKey: must be a non-empty Buffer');
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

  if (typeof secretKey === 'string' && secretKey.length === 0) {
    return false;
  }

  if (Buffer.isBuffer(secretKey) && secretKey.length === 0) {
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
  const fullChain = typeof ledger.getFullChain === 'function' ? ledger.getFullChain() : ledger.chain;

  if (options.block && typeof options.block === 'object') {
    const candidate = options.block;
    // Verify candidate belongs to this ledger chain
    const found = fullChain.find(b => b.index === candidate.index && b.hash === candidate.hash);
    if (!found) {
      throw new Error(`Target block #${candidate.index} (${candidate.hash}) not found in ledger chain`);
    }
    targetBlock = found;
  } else if (typeof options.blockIndex === 'number') {
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

  // Refuse to record checkpoint for a block whose payload hash is corrupted
  const computedHash = AuditBlock.calculateHash(
    targetBlock.index,
    targetBlock.timestamp,
    targetBlock.prevHash,
    targetBlock.event
  );
  if (computedHash !== targetBlock.hash) {
    throw new Error(
      `Cannot attest tampered block #${targetBlock.index}: payload hash mismatch`
    );
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
 * @param {AuditBlock|number} checkpointBlock - The block or block index containing the ATTESTATION_CHECKPOINT event
 * @param {string|Buffer|Function|Object} secretKey - The operator secret key, key lookup function, or operator key map
 * @returns {{ valid: boolean, error?: string, targetBlock?: AuditBlock, checkpointBlock?: AuditBlock, operatorId?: string }}
 */
function verifyAttestationCheckpoint(ledger, checkpointBlock, secretKey) {
  if (!ledger || (typeof ledger.getFullChain !== 'function' && !Array.isArray(ledger.chain))) {
    return { valid: false, error: 'Invalid ledger instance' };
  }

  const fullChain = typeof ledger.getFullChain === 'function' ? ledger.getFullChain() : ledger.chain;

  let cpBlock = checkpointBlock;
  if (typeof checkpointBlock === 'number') {
    cpBlock = fullChain.find(b => b.index === checkpointBlock);
    if (!cpBlock) {
      return { valid: false, error: `Checkpoint block #${checkpointBlock} not found in ledger` };
    }
  }

  if (!cpBlock || !cpBlock.event) {
    return { valid: false, error: 'Invalid checkpoint block' };
  }

  const evt = cpBlock.event;
  if (evt.type !== ATTESTATION_EVENT_TYPE) {
    return { valid: false, error: `Block event type is not ${ATTESTATION_EVENT_TYPE}` };
  }

  // Resolve key for operator if key map / function was provided
  let key = secretKey;
  if (typeof secretKey === 'function') {
    key = secretKey(evt.operatorId, cpBlock);
  } else if (secretKey instanceof Map) {
    key = secretKey.get(evt.operatorId);
  } else if (typeof secretKey === 'object' && secretKey !== null && !Buffer.isBuffer(secretKey)) {
    key = secretKey[evt.operatorId];
  }

  if (!key) {
    return {
      valid: false,
      error: `No cryptographic key provided for operator '${evt.operatorId || 'unknown'}'`,
      operatorId: evt.operatorId
    };
  }

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

  const isSigValid = verifyAttestation(targetBlock, key, evt.signature);
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
    checkpointBlock: cpBlock,
    operatorId: evt.operatorId,
    timestamp: evt.checkpointTimestamp
  };
}

/**
 * Scans the entire ledger chain for all ATTESTATION_CHECKPOINT events and cryptographically verifies each one.
 *
 * @param {AuditLedger} ledger
 * @param {string|Buffer|Function|Object} secretKey - Secret key, operator key map, or resolver function
 * @param {Object} [options]
 * @param {string} [options.operatorId] - Filter verification to checkpoints matching specific operator ID
 * @returns {{ valid: boolean, checkpointCount: number, verifiedCount: number, failures: Array<Object> }}
 */
function verifyAllAttestations(ledger, secretKey, options = {}) {
  if (!ledger || (typeof ledger.getFullChain !== 'function' && !Array.isArray(ledger.chain))) {
    throw new TypeError('Invalid ledger: must be an instance of AuditLedger');
  }

  let opts = options;
  let keyOrMap = secretKey;
  if (
    typeof secretKey === 'object' &&
    secretKey !== null &&
    !Buffer.isBuffer(secretKey) &&
    !(secretKey instanceof Map) &&
    (options === undefined || Object.keys(options).length === 0)
  ) {
    if (secretKey.operatorKeys || secretKey.secretKey || secretKey.keys) {
      opts = secretKey;
      keyOrMap = secretKey.operatorKeys || secretKey.secretKey || secretKey.keys;
    }
  }

  const fullChain = typeof ledger.getFullChain === 'function' ? ledger.getFullChain() : ledger.chain;
  let checkpoints = fullChain.filter(b => b.event && b.event.type === ATTESTATION_EVENT_TYPE);
  if (opts && opts.operatorId) {
    checkpoints = checkpoints.filter(b => b.event.operatorId === opts.operatorId);
  }

  const failures = [];
  let verifiedCount = 0;

  for (const cp of checkpoints) {
    const res = verifyAttestationCheckpoint(ledger, cp, keyOrMap);
    if (res.valid) {
      verifiedCount++;
    } else {
      failures.push({
        checkpointIndex: cp.index,
        targetBlockIndex: cp.event ? cp.event.targetBlockIndex : null,
        operatorId: cp.event ? cp.event.operatorId : null,
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
    this.checkpointType = options.checkpointType || 'PERIODIC';
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
      checkpointType: this.checkpointType,
      ...options
    });
  }

  verifyCheckpoint(ledger, checkpointBlock) {
    return verifyAttestationCheckpoint(ledger, checkpointBlock, this.secretKey);
  }

  verifyAll(ledger, options = {}) {
    return verifyAllAttestations(ledger, this.secretKey, {
      operatorId: this.operatorId,
      ...options
    });
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
