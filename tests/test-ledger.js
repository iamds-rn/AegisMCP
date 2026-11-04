/**
 * Tests for AegisMCP Cryptographic Audit Ledger
 */

'use strict';

const assert = require('node:assert');
const { AuditLedger, AuditBlock, sha256 } = require('../src/ledger/auditLedger');

function runLedgerTests() {
  console.log('🧪 Testing Cryptographic Audit Ledger...');

  const ledger = new AuditLedger();

  // 1. Genesis Block integrity
  assert.strictEqual(ledger.chain.length, 1, 'Initial chain must have genesis block');
  const genesis = ledger.chain[0];
  assert.strictEqual(genesis.index, 0, 'Genesis index must be 0');
  assert.strictEqual(genesis.prevHash, '0000000000000000000000000000000000000000000000000000000000000000');
  assert(genesis.hash.length === 64, 'Genesis hash must be 64-character SHA-256 hex');

  // 2. Initial verification passes
  let verifyResult = ledger.verify();
  assert(verifyResult.valid, 'Genesis block verification must pass');
  assert.strictEqual(verifyResult.blockCount, 1);

  // 3. Append events and check chaining
  const b1 = ledger.append('TOOL_CALL', { tool: 'read_file', path: '/workspace/project.json' });
  assert.strictEqual(b1.index, 1);
  assert.strictEqual(b1.prevHash, genesis.hash, 'Block 1 prevHash must match Genesis hash');

  const b2 = ledger.append('FIREWALL_BLOCK', { tool: 'read_file', ruleId: 'SEC-001', threat: 'Directory Traversal' });
  assert.strictEqual(b2.index, 2);
  assert.strictEqual(b2.prevHash, b1.hash, 'Block 2 prevHash must match Block 1 hash');

  const b3 = ledger.append('PIPELINE_EXEC', { pipelineId: 'pipeline-alpha', steps: 4 });
  assert.strictEqual(b3.index, 3);
  assert.strictEqual(b3.prevHash, b2.hash, 'Block 3 prevHash must match Block 2 hash');

  // 4. Verification with 4 blocks
  verifyResult = ledger.verify();
  assert(verifyResult.valid, 'Multi-block chain verification must pass');
  assert.strictEqual(verifyResult.blockCount, 4);
  assert.strictEqual(verifyResult.headHash, b3.hash);

  // 5. Proof export
  const proof = ledger.exportProof();
  assert.strictEqual(proof.integrityStatus, 'VERIFIED_PRISTINE');
  assert.strictEqual(proof.blockCount, 4);
  assert.strictEqual(proof.blocks.length, 4);

  // 6. Adversarial Tamper Detection
  // Simulate an attacker covertly modifying block #1 to erase an audit trail
  console.log('  Testing adversarial tamper detection...');
  ledger.tamper(1, { tool: 'read_file', path: '/workspace/falsified_record.txt' });

  const tamperedVerify = ledger.verify();
  assert(!tamperedVerify.valid, 'Ledger verification must fail on tampered chain!');
  assert.strictEqual(tamperedVerify.brokenIndex, 1, 'Verification must pinpoint exact broken block index 1');

  // 7. Verify Proof shows COMPROMISED
  const compromisedProof = ledger.exportProof();
  assert.strictEqual(compromisedProof.integrityStatus, 'COMPROMISED');

  console.log('✅ Cryptographic Audit Ledger: All 7 test cases passed!');
}

module.exports = { runLedgerTests };

if (require.main === module) {
  runLedgerTests();
}
