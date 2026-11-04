/**
 * AegisMCP - Milestone 3 Dedicated Unit & Integration Test Suite
 *
 * Verifies:
 * 1. File Persistence for Cryptographic Audit Ledger (src/ledger/filePersistence.js)
 *    - Append-only streaming JSONL persistence for AuditBlock records.
 *    - Line-by-line reading, deserialization, and schema validation.
 *    - Cryptographic re-verification of hash chain continuity:
 *      H_i = SHA-256(i || t || H_{i-1} || canonicalEvent).
 *    - State reconstruction into pristine AuditLedger instances.
 *    - Atomic sync (fsyncSync) and buffered flush with crash safety.
 *    - Adversarial disk tampering, sequence gaps, and corrupted write handling.
 *
 * 2. Cryptographic HMAC-SHA256 Attestation Signatures (src/ledger/attestation.js)
 *    - Operator block attestation: HMAC-SHA256(secretKey, block.hash).
 *    - Constant-time verification (verifyAttestation) preventing timing side channels.
 *    - ATTESTATION_CHECKPOINT events recorded directly into the hash chain.
 *    - Checkpoint verification against referenced target blocks and operator keys.
 *    - Full-chain attestation sweeps and LedgerAttestor operator interface.
 *
 * 3. End-to-End Stress & Crash-Recovery Lifecycle
 *    - 100+ block persistent streaming with multi-operator checkpoints.
 *    - Cold-start restart recovery, verification, and append continuation.
 */

'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const { AuditBlock, AuditLedger, GENESIS_PREV_HASH } = require('../src/ledger/auditLedger');
const {
  AuditFilePersistence,
  FilePersistence,
  LedgerPersistenceError
} = require('../src/ledger/filePersistence');
const {
  attestBlock,
  verifyAttestation,
  recordAttestationCheckpoint,
  createAttestationCheckpoint,
  verifyAttestationCheckpoint,
  verifyAllAttestations,
  LedgerAttestor,
  ATTESTATION_EVENT_TYPE
} = require('../src/ledger/attestation');

// Helper to create safe unique scratch test directories
function createTestDir(prefix = 'aegis-test-ledger') {
  const dir = path.join(os.tmpdir(), `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

// Helper to clean up test directories
function removeTestDir(dir) {
  try {
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  } catch {
    // Ignore cleanup errors in temp dirs
  }
}

async function runLedgerPersistenceTests() {
  console.log('🧪 Testing Milestone 3 Ledger File Persistence & HMAC-SHA256 Attestation...');
  const tempDir = createTestDir();

  try {
    // =========================================================================
    // SECTION 1: File Persistence Unit & Core Serialization
    // =========================================================================
    console.log('  [Section 1] AuditFilePersistence Unit & Schema Serialization...');
    {
      const filePath = path.join(tempDir, 'unit-persistence.jsonl');
      const persistence = new AuditFilePersistence(filePath);
      assert.strictEqual(AuditFilePersistence, FilePersistence, 'FilePersistence alias must match');

      // 1. Serialization
      const block = new AuditBlock(0, '2026-11-04T00:00:00.000Z', GENESIS_PREV_HASH, { type: 'GENESIS' });
      const line = persistence.serializeBlock(block);
      assert.strictEqual(typeof line, 'string');
      assert(!line.includes('\n'), 'Serialized JSONL line must not contain unescaped newline');

      // 2. Deserialization
      const deserialized = persistence.deserializeBlock(line, 1);
      assert.strictEqual(deserialized.index, 0);
      assert.strictEqual(deserialized.prevHash, GENESIS_PREV_HASH);
      assert.strictEqual(deserialized.hash, block.hash);
      assert.deepStrictEqual(deserialized.event, { type: 'GENESIS' });

      // 3. Reject malformed JSON
      assert.throws(
        () => persistence.deserializeBlock('{"index": 1, invalid_json', 2),
        err => err instanceof LedgerPersistenceError && err.code === 'ERR_MALFORMED_JSON'
      );

      // 4. Reject invalid schema
      assert.throws(
        () => persistence.deserializeBlock(JSON.stringify({ index: 1 }), 3),
        err => err instanceof LedgerPersistenceError && err.code === 'ERR_INVALID_SCHEMA'
      );

      // 5. Require valid filePath
      assert.throws(() => new AuditFilePersistence(null), /filePath is required/);
      assert.throws(() => new AuditFilePersistence(''), /filePath is required/);

      console.log('    ✔ Unit serialization and schema invariants PASSED');
    }

    // =========================================================================
    // SECTION 2: Atomic Sync & Buffered Write Modes
    // =========================================================================
    console.log('  [Section 2] Atomic Sync (fsync) & Buffered Flush Modes...');
    {
      // 1. Immediate Atomic Sync Mode
      const atomicPath = path.join(tempDir, 'atomic-sync.jsonl');
      const atomicPersistence = new AuditFilePersistence(atomicPath, { atomicSync: true, fsync: true });

      const b0 = new AuditBlock(0, '2026-11-04T00:00:00.000Z', GENESIS_PREV_HASH, { type: 'GENESIS' });
      atomicPersistence.appendBlock(b0);

      // File must physically exist and contain exactly 1 line immediately
      assert(fs.existsSync(atomicPath), 'File must exist immediately after atomic append');
      let lines = fs.readFileSync(atomicPath, 'utf8').trim().split('\n');
      assert.strictEqual(lines.length, 1);

      const b1 = new AuditBlock(1, new Date().toISOString(), b0.hash, { type: 'TOOL_CALL', tool: 'eval' });
      atomicPersistence.appendBlock(b1);
      lines = fs.readFileSync(atomicPath, 'utf8').trim().split('\n');
      assert.strictEqual(lines.length, 2);

      // 2. Buffered Flush Mode
      const bufferedPath = path.join(tempDir, 'buffered-flush.jsonl');
      const bufferedPersistence = new AuditFilePersistence(bufferedPath, {
        buffered: true,
        bufferSize: 3,
        fsync: true
      });

      bufferedPersistence.appendBlock(b0);
      bufferedPersistence.appendBlock(b1);

      // File should not exist or be empty before bufferSize is reached
      const existsBefore = fs.existsSync(bufferedPath) && fs.readFileSync(bufferedPath, 'utf8').length > 0;
      assert(!existsBefore, 'Writes must be held in memory buffer before threshold');

      const b2 = new AuditBlock(2, new Date().toISOString(), b1.hash, { type: 'SYSTEM_EVENT', status: 'OK' });
      bufferedPersistence.appendBlock(b2); // Reaches bufferSize = 3, auto-flushes

      assert(fs.existsSync(bufferedPath));
      let bufLines = fs.readFileSync(bufferedPath, 'utf8').trim().split('\n');
      assert.strictEqual(bufLines.length, 3, 'Auto-flush must commit all 3 lines to disk');

      // Manual flush test
      const b3 = new AuditBlock(3, new Date().toISOString(), b2.hash, { type: 'TOOL_CALL', tool: 'write_file' });
      bufferedPersistence.appendBlock(b3); // Buffered (1 in buffer)
      bufLines = fs.readFileSync(bufferedPath, 'utf8').trim().split('\n');
      assert.strictEqual(bufLines.length, 3, 'Single block remains buffered');

      bufferedPersistence.flush(); // Force manual atomic flush
      bufLines = fs.readFileSync(bufferedPath, 'utf8').trim().split('\n');
      assert.strictEqual(bufLines.length, 4, 'Manual flush must commit pending writes with fsync');

      // Close method
      bufferedPersistence.close();

      console.log('    ✔ Atomic sync and buffered flush modes PASSED');
    }

    // =========================================================================
    // SECTION 3: Hash Chain Continuity & State Reconstruction
    // =========================================================================
    console.log('  [Section 3] Hash Chain Continuity & Cold-Start State Reconstruction...');
    {
      const ledgerPath = path.join(tempDir, 'state-reconstruction.jsonl');

      // Step 1: Create ledger and write events
      const originalLedger = new AuditLedger({ persistenceFilePath: ledgerPath });
      assert(originalLedger.persistence !== null);
      assert.strictEqual(originalLedger.chain.length, 1); // Genesis created and persisted

      const b1 = originalLedger.append('TOOL_CALL', { tool: 'read_memory', address: '0x7fff' });
      const b2 = originalLedger.append('FIREWALL_BLOCK', { ruleId: 'SEC-001', threat: 'Directory Traversal' });
      const b3 = originalLedger.append('SECRET_SCAN', { detectedTokens: 0, status: 'CLEAN' });

      assert.strictEqual(originalLedger.chain.length, 4);
      const originalVerification = originalLedger.verify();
      assert(originalVerification.valid);

      // Step 2: Read line-by-line and verify with AuditFilePersistence directly
      const persistence = new AuditFilePersistence(ledgerPath);
      const recoveredBlocks = persistence.recoverBlocks();
      assert.strictEqual(recoveredBlocks.length, 4);

      for (let i = 0; i < 4; i++) {
        assert.strictEqual(recoveredBlocks[i].index, originalLedger.chain[i].index);
        assert.strictEqual(recoveredBlocks[i].prevHash, originalLedger.chain[i].prevHash);
        assert.strictEqual(recoveredBlocks[i].hash, originalLedger.chain[i].hash);
        assert.deepStrictEqual(recoveredBlocks[i].event, originalLedger.chain[i].event);
      }

      // Step 3: Stream blocks using async generator
      const streamed = [];
      for await (const block of persistence.streamBlocks()) {
        streamed.push(block);
      }
      assert.strictEqual(streamed.length, 4);
      assert.strictEqual(streamed[3].hash, b3.hash);

      // Step 4: Reconstruct full AuditLedger instance via static factory
      const restoredLedger = AuditLedger.loadFromFile(ledgerPath);
      assert.strictEqual(restoredLedger.chain.length, 4);
      const restoredVerification = restoredLedger.verify();
      assert(restoredVerification.valid);
      assert.strictEqual(restoredVerification.headHash, b3.hash);

      // Step 5: Continue appending to restored ledger
      const b4 = restoredLedger.append('PIPELINE_EXEC', { pipelineId: 'pipeline-omega', steps: 5 });
      assert.strictEqual(b4.index, 4);
      assert.strictEqual(b4.prevHash, b3.hash);
      assert.strictEqual(restoredLedger.chain.length, 5);
      assert(restoredLedger.verify().valid);

      // Step 6: Verify file on disk has grown to 5 lines seamlessly
      const updatedLines = fs.readFileSync(ledgerPath, 'utf8').trim().split('\n');
      assert.strictEqual(updatedLines.length, 5);

      // Step 7: Memory bounding + persistence integration
      const boundedPath = path.join(tempDir, 'bounded-persistence.jsonl');
      const boundedLedger = new AuditLedger({
        persistenceFilePath: boundedPath,
        maxMemoryBlocks: 3
      });

      for (let i = 0; i < 7; i++) {
        boundedLedger.append('EVENT_STEP', { step: i });
      }

      // In memory: 3 active, 5 archived (1 genesis + 7 events = 8 total)
      assert.strictEqual(boundedLedger.chain.length, 3);
      assert.strictEqual(boundedLedger.archivedBlocks.length, 5);
      assert(boundedLedger.verify().valid);

      // Recovering bounded ledger from disk
      const recoveredBounded = AuditLedger.loadFromFile(boundedPath, { maxMemoryBlocks: 3 });
      assert.strictEqual(recoveredBounded.chain.length, 3);
      assert.strictEqual(recoveredBounded.archivedBlocks.length, 5);
      assert(recoveredBounded.verify().valid);
      assert.strictEqual(recoveredBounded.getFullChain().length, 8);

      console.log('    ✔ Hash chain continuity & state reconstruction PASSED');
    }

    // =========================================================================
    // SECTION 4: Adversarial Disk Tampering & Fault Injections
    // =========================================================================
    console.log('  [Section 4] Adversarial Disk Tampering & Integrity Fault Injections...');
    {
      const baseLedgerPath = path.join(tempDir, 'adversarial-base.jsonl');
      const baseLedger = new AuditLedger({ persistenceFilePath: baseLedgerPath });
      baseLedger.append('TOOL_CALL', { tool: 'fetch', url: 'https://internal.net' });
      baseLedger.append('TOOL_CALL', { tool: 'eval', code: 'safeCode()' });
      baseLedger.append('SECURITY_ALERT', { level: 'HIGH', detail: 'Suspicious payload' });

      const originalLines = fs.readFileSync(baseLedgerPath, 'utf8').trim().split('\n');
      assert.strictEqual(originalLines.length, 4);

      // Fault 1: Adversary alters event payload on disk (tampering with audit log)
      const tamperedPayloadPath = path.join(tempDir, 'tampered-payload.jsonl');
      const tamperedLines = [...originalLines];
      const parsedBlock2 = JSON.parse(tamperedLines[2]);
      parsedBlock2.event.code = 'maliciousCode(); dropTables();'; // Covert alteration without updating hash
      tamperedLines[2] = JSON.stringify(parsedBlock2);
      fs.writeFileSync(tamperedPayloadPath, tamperedLines.join('\n') + '\n');

      const tamperedPersistence = new AuditFilePersistence(tamperedPayloadPath);
      assert.throws(
        () => tamperedPersistence.recoverBlocks(),
        err => err instanceof LedgerPersistenceError &&
               err.code === 'ERR_HASH_MISMATCH' &&
               err.brokenIndex === 2,
        'Must detect modified event payload hash mismatch'
      );
      const diag1 = tamperedPersistence.verifyFile();
      assert(!diag1.valid);
      assert.strictEqual(diag1.brokenIndex, 2);

      // Fault 2: Broken hash pointer (prevHash altered)
      const tamperedPointerPath = path.join(tempDir, 'tampered-pointer.jsonl');
      const pointerLines = [...originalLines];
      const parsedBlock3 = JSON.parse(pointerLines[3]);
      parsedBlock3.prevHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
      // Recalculate block hash so block hash matches, but prevHash chain pointer is broken
      parsedBlock3.hash = AuditBlock.calculateHash(
        parsedBlock3.index,
        parsedBlock3.timestamp,
        parsedBlock3.prevHash,
        parsedBlock3.event
      );
      pointerLines[3] = JSON.stringify(parsedBlock3);
      fs.writeFileSync(tamperedPointerPath, pointerLines.join('\n') + '\n');

      const pointerPersistence = new AuditFilePersistence(tamperedPointerPath);
      assert.throws(
        () => pointerPersistence.recoverBlocks(),
        err => err instanceof LedgerPersistenceError &&
               err.code === 'ERR_PREV_HASH_MISMATCH' &&
               err.brokenIndex === 3,
        'Must detect broken hash chain pointer'
      );

      // Fault 3: Sequence gap on disk (block #2 deleted)
      const gapPath = path.join(tempDir, 'sequence-gap.jsonl');
      const gapLines = [originalLines[0], originalLines[1], originalLines[3]]; // Line 2 omitted
      fs.writeFileSync(gapPath, gapLines.join('\n') + '\n');

      const gapPersistence = new AuditFilePersistence(gapPath);
      assert.throws(
        () => gapPersistence.recoverBlocks(),
        err => err instanceof LedgerPersistenceError &&
               err.code === 'ERR_SEQUENCE_GAP' &&
               err.brokenIndex === 3,
        'Must detect sequence gap from deleted block'
      );

      // Fault 4: Partial write / truncated trailing line (simulating sudden crash mid-write)
      const partialPath = path.join(tempDir, 'partial-write.jsonl');
      const partialLines = [...originalLines];
      partialLines[3] = '{"index": 3, "timestamp": "2026-11-04T00:01:00.000Z", "prevHash": "abc'; // Truncated
      fs.writeFileSync(partialPath, partialLines.join('\n') + '\n');

      const partialPersistence = new AuditFilePersistence(partialPath);
      assert.throws(
        () => partialPersistence.recoverBlocks(),
        err => err instanceof LedgerPersistenceError && err.code === 'ERR_MALFORMED_JSON',
        'Must detect truncated partial JSON record'
      );

      // Fault 5: Corrupted Genesis Block
      const badGenesisPath = path.join(tempDir, 'bad-genesis.jsonl');
      const badGenesisLines = [...originalLines];
      const parsedGen = JSON.parse(badGenesisLines[0]);
      parsedGen.prevHash = '1234567890123456789012345678901234567890123456789012345678901234';
      badGenesisLines[0] = JSON.stringify(parsedGen);
      fs.writeFileSync(badGenesisPath, badGenesisLines.join('\n') + '\n');

      const badGenPersistence = new AuditFilePersistence(badGenesisPath);
      assert.throws(
        () => badGenPersistence.recoverBlocks(),
        err => err instanceof LedgerPersistenceError &&
               (err.code === 'ERR_INVALID_GENESIS_PREV_HASH' || err.code === 'ERR_HASH_MISMATCH')
      );

      console.log('    ✔ Adversarial disk tampering & fault injections PASSED');
    }

    // =========================================================================
    // SECTION 5: HMAC-SHA256 Cryptographic Attestation Signatures
    // =========================================================================
    console.log('  [Section 5] HMAC-SHA256 Cryptographic Attestation Signatures...');
    {
      const secretKey = 'aegis-master-operator-secret-key-32b';
      const secondaryKey = 'backup-auditor-secret-key-32b';

      const block = new AuditBlock(
        42,
        '2026-11-04T12:00:00.000Z',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        { type: 'CHECKPOINT_TARGET', data: 'critical-state' }
      );

      // 1. Signature generation
      const signature = attestBlock(block, secretKey);
      assert.strictEqual(typeof signature, 'string');
      assert.strictEqual(signature.length, 64, 'HMAC-SHA256 hex signature must be 64 characters');
      assert(/^[0-9a-f]{64}$/.test(signature), 'Signature must be lowercase hex');

      // 2. Determinism
      const sig2 = attestBlock(block, secretKey);
      assert.strictEqual(signature, sig2, 'HMAC signature must be deterministic');

      // 3. Key sensitivity
      const sigDiffKey = attestBlock(block, secondaryKey);
      assert.notStrictEqual(signature, sigDiffKey, 'Different key must produce different signature');

      // 4. Verification with correct key
      assert.strictEqual(verifyAttestation(block, secretKey, signature), true);
      assert.strictEqual(verifyAttestation(block, secretKey, { signature }), true, 'Supports object wrapper');

      // 5. Verification failure with wrong key
      assert.strictEqual(verifyAttestation(block, secondaryKey, signature), false);

      // 6. Verification failure with altered block
      const alteredBlock = new AuditBlock(block.index, block.timestamp, block.prevHash, { altered: true });
      assert.strictEqual(verifyAttestation(alteredBlock, secretKey, signature), false);

      // 7. Verification failure with corrupt / invalid signature
      assert.strictEqual(verifyAttestation(block, secretKey, 'bad_signature'), false);
      assert.strictEqual(verifyAttestation(block, secretKey, null), false);
      assert.strictEqual(verifyAttestation(block, secretKey, ''), false);
      assert.strictEqual(verifyAttestation(block, secretKey, signature.slice(0, 63) + '0'), false);

      // 8. Parameter validation
      assert.throws(() => attestBlock(null, secretKey), TypeError);
      assert.throws(() => attestBlock({}, secretKey), TypeError);
      assert.throws(() => attestBlock(block, null), TypeError);
      assert.throws(() => attestBlock(block, ''), TypeError);

      console.log('    ✔ HMAC-SHA256 signature and constant-time verification PASSED');
    }

    // =========================================================================
    // SECTION 6: ATTESTATION_CHECKPOINT In-Chain Recording & Verification
    // =========================================================================
    console.log('  [Section 6] In-Chain ATTESTATION_CHECKPOINT Recording & Verification...');
    {
      const operatorSecret = 'top-secret-operator-key-2026';
      const ledger = new AuditLedger();

      // Append standard operations
      const t1 = ledger.append('TOOL_CALL', { tool: 'read_file', path: '/etc/hosts' });
      const t2 = ledger.append('TOOL_CALL', { tool: 'dns_lookup', host: 'api.internal' });

      // Record attestation checkpoint of latest block (#2)
      const cpBlock = recordAttestationCheckpoint(ledger, operatorSecret, {
        operatorId: 'operator-alice',
        checkpointType: 'SECURITY_AUDIT',
        notes: 'Compliance sweep clean'
      });

      assert.strictEqual(cpBlock.index, 3);
      assert.strictEqual(cpBlock.event.type, ATTESTATION_EVENT_TYPE);
      assert.strictEqual(cpBlock.event.targetBlockIndex, t2.index);
      assert.strictEqual(cpBlock.event.targetBlockHash, t2.hash);
      assert.strictEqual(cpBlock.event.operatorId, 'operator-alice');
      assert.strictEqual(cpBlock.event.signature.length, 64);

      // Full hash chain remains intact
      const verifyRes = ledger.verify();
      assert(verifyRes.valid, 'Hash chain including ATTESTATION_CHECKPOINT must be valid');
      assert.strictEqual(verifyRes.blockCount, 4);

      // Verify checkpoint against target block
      const cpVerify = verifyAttestationCheckpoint(ledger, cpBlock, operatorSecret);
      assert(cpVerify.valid, 'Checkpoint verification must pass');
      assert.strictEqual(cpVerify.operatorId, 'operator-alice');

      // Verify checkpoint fails with wrong operator key
      const badKeyVerify = verifyAttestationCheckpoint(ledger, cpBlock, 'wrong-key');
      assert(!badKeyVerify.valid);
      assert(badKeyVerify.error.includes('signature verification failed'));

      // Checkpoint of specific historical block (#1)
      const cpHistBlock = recordAttestationCheckpoint(ledger, operatorSecret, {
        block: t1,
        operatorId: 'compliance-bot'
      });
      assert.strictEqual(cpHistBlock.event.targetBlockIndex, 1);
      assert.strictEqual(cpHistBlock.event.targetBlockHash, t1.hash);
      assert(verifyAttestationCheckpoint(ledger, cpHistBlock, operatorSecret).valid);

      // Full-chain attestation sweep: verifyAllAttestations
      const allRes = verifyAllAttestations(ledger, operatorSecret);
      assert(allRes.valid);
      assert.strictEqual(allRes.checkpointCount, 2);
      assert.strictEqual(allRes.verifiedCount, 2);
      assert.strictEqual(allRes.failures.length, 0);

      // Adversarial test: Tamper with target block #2
      ledger.tamper(2, { tool: 'tampered_tool', path: '/etc/shadow' });
      assert(!ledger.verify().valid, 'Ledger chain detects tampering');

      const tamperedCpVerify = verifyAttestationCheckpoint(ledger, cpBlock, operatorSecret);
      assert(!tamperedCpVerify.valid, 'Checkpoint must detect target block tampering');
      assert(tamperedCpVerify.error.includes('mismatch'));

      // Restore and re-verify
      ledger.restoreAll();
      assert(ledger.verify().valid);
      assert(verifyAttestationCheckpoint(ledger, cpBlock, operatorSecret).valid);

      // Test LedgerAttestor class
      const attestor = new LedgerAttestor(operatorSecret, { operatorId: 'lead-secops' });
      const cpViaAttestor = attestor.checkpoint(ledger, { notes: 'Attestor class test' });
      assert.strictEqual(cpViaAttestor.event.operatorId, 'lead-secops');
      assert(attestor.verifyCheckpoint(ledger, cpViaAttestor).valid);

      // Test AuditLedger prototype integration methods
      const cpProto = ledger.attestCheckpoint(operatorSecret, { operatorId: 'proto-tester' });
      assert(ledger.verifyAttestationCheckpoint(cpProto, operatorSecret).valid);
      const sweepProto = ledger.verifyAllAttestations(operatorSecret);
      assert(sweepProto.valid);
      assert.strictEqual(sweepProto.checkpointCount, 4);

      console.log('    ✔ In-chain ATTESTATION_CHECKPOINT recording & verification PASSED');
    }

    // =========================================================================
    // SECTION 7: End-to-End Persistence + Multi-Operator Attestation Stress
    // =========================================================================
    console.log('  [Section 7] End-to-End Persistence + Multi-Operator Attestation Lifecycle...');
    {
      const e2ePath = path.join(tempDir, 'e2e-persistent-ledger.jsonl');
      const secKeyA = 'secops-key-alpha-32-bytes-long!';
      const secKeyB = 'compliance-key-beta-32-bytes!!';

      // 1. Initialize persistent ledger
      const persistentLedger = new AuditLedger({
        persistenceFilePath: e2ePath,
        atomicSync: true,
        fsync: true
      });

      // 2. High-throughput stream: append 100 events with periodic checkpoints
      const totalEvents = 100;
      for (let i = 1; i <= totalEvents; i++) {
        persistentLedger.append('TRANSACTION_LOG', {
          txId: `tx-${i}`,
          client: `agent-${i % 5}`,
          amount: (i * 13.37).toFixed(2)
        });

        // Seal attestation checkpoints at regular intervals
        if (i === 25 || i === 75) {
          persistentLedger.attestCheckpoint(secKeyA, {
            operatorId: 'operator-alpha',
            notes: `Milestone checkpoint at step ${i}`
          });
        } else if (i === 50 || i === 100) {
          persistentLedger.attestCheckpoint(secKeyB, {
            operatorId: 'auditor-beta',
            notes: `Compliance checkpoint at step ${i}`
          });
        }
      }

      // Genesis (1) + 100 events + 4 checkpoints = 105 blocks
      assert.strictEqual(persistentLedger.chain.length, 105);
      const preRestartVerify = persistentLedger.verify();
      assert(preRestartVerify.valid);
      assert.strictEqual(preRestartVerify.blockCount, 105);
      const headHashBefore = persistentLedger.getLatestBlock().hash;

      // 3. Cold restart: simulate application restart, loading directly from disk
      const recoveredLedger = AuditLedger.loadFromFile(e2ePath);
      assert.strictEqual(recoveredLedger.chain.length, 105);

      const coldVerify = recoveredLedger.verify();
      assert(coldVerify.valid, 'Recovered ledger must verify 100% against hash chain');
      assert.strictEqual(coldVerify.blockCount, 105);
      assert.strictEqual(recoveredLedger.getLatestBlock().hash, headHashBefore);

      // 4. Verify all checkpoints under respective operator keys
      const allCheckpoints = recoveredLedger.chain.filter(
        b => b.event.type === ATTESTATION_EVENT_TYPE
      );
      assert.strictEqual(allCheckpoints.length, 4);

      // Verify Alpha checkpoints (indices 0 and 2 of checkpoints)
      assert(verifyAttestationCheckpoint(recoveredLedger, allCheckpoints[0], secKeyA).valid);
      assert(verifyAttestationCheckpoint(recoveredLedger, allCheckpoints[2], secKeyA).valid);
      assert(!verifyAttestationCheckpoint(recoveredLedger, allCheckpoints[0], secKeyB).valid);

      // Verify Beta checkpoints (indices 1 and 3 of checkpoints)
      assert(verifyAttestationCheckpoint(recoveredLedger, allCheckpoints[1], secKeyB).valid);
      assert(verifyAttestationCheckpoint(recoveredLedger, allCheckpoints[3], secKeyB).valid);
      assert(!verifyAttestationCheckpoint(recoveredLedger, allCheckpoints[1], secKeyA).valid);

      // 5. Continue operations on recovered ledger
      const bNext = recoveredLedger.append('POST_RESTART_EVENT', { recovered: true });
      assert.strictEqual(bNext.index, 105);
      assert.strictEqual(bNext.prevHash, headHashBefore);

      // Attest post-restart state
      const cpPost = recoveredLedger.attestCheckpoint(secKeyA, { operatorId: 'operator-alpha' });
      assert.strictEqual(cpPost.index, 106);
      assert(recoveredLedger.verify().valid);

      // Check on-disk file has exactly 107 lines now
      const finalDiskLines = fs.readFileSync(e2ePath, 'utf8').trim().split('\n');
      assert.strictEqual(finalDiskLines.length, 107);

      console.log('    ✔ End-to-end persistent ledger + multi-operator attestation PASSED (107 blocks)');
    }

    console.log('✅ Milestone 3 Features: All persistence, attestation, and recovery tests passed!');
  } finally {
    removeTestDir(tempDir);
  }
}

module.exports = { runLedgerPersistenceTests };

if (require.main === module) {
  runLedgerPersistenceTests().catch(err => {
    console.error('Fatal Test Failure:', err);
    process.exit(1);
  });
}
