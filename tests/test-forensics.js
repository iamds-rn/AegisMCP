/**
 * Tests for AegisMCP Time-Travel Forensics & Tamper Localization
 */

'use strict';

const assert = require('node:assert');
const { AuditLedger } = require('../src/ledger/auditLedger');

function runForensicsTests() {
  console.log('🧪 Testing Time-Travel Ledger Forensics & Tamper Localization...');

  const ledger = new AuditLedger();
  ledger.append('TOOL_CALL', { tool: 'read_file', path: '/workspace/project.json', user: 'agent-1' });
  ledger.append('FIREWALL_BLOCK', { tool: 'write_file', ruleId: 'SEC-001', threat: 'Directory Traversal' });
  ledger.append('TOOL_CALL', { tool: 'list_files', path: '/workspace', user: 'agent-1' });
  ledger.append('PIPELINE_EXEC', { pipelineId: 'pipeline-alpha', steps: 3 });

  // 1. Pristine forensics
  const pristineReport = ledger.locateTamper();
  assert(pristineReport.intact, 'Pristine chain must report intact: true');
  assert.strictEqual(pristineReport.blockCount, 5); // Genesis + 4
  assert(pristineReport.forensicSummary.includes('PRISTINE'));

  // 2. Tamper localization at block #2
  ledger.tamper(2, {
    tool: 'write_file',
    ruleId: 'SEC-001',
    threat: 'Covert Manipulation by Attacker',
    spoofedLog: true
  });

  const tamperedReport = ledger.locateTamper();
  assert(!tamperedReport.intact, 'Tampered chain must report intact: false');
  assert.strictEqual(tamperedReport.tamperedIndex, 2, 'Must localize tamper directly to block #2');
  assert.strictEqual(tamperedReport.cascadeBlastRadius, 3, 'Blast radius must be 3 downstream blocks (2, 3, 4)');
  assert.deepStrictEqual(tamperedReport.invalidatedIndices, [2, 3, 4]);

  // 3. Field diff verification
  assert(tamperedReport.fieldDiff, 'Must compute field diff when pristine backup exists');
  assert(tamperedReport.fieldDiff.changedKeys.some(c => c.key === 'threat'));
  assert(tamperedReport.fieldDiff.changedKeys.some(c => c.key === 'spoofedLog'));

  // 4. Time-Travel Historical State Snapshot
  const snap0 = ledger.getSnapshotAtBlock(0);
  assert.strictEqual(snap0.targetIndex, 0);
  assert.strictEqual(snap0.event.type, 'GENESIS');
  assert.strictEqual(snap0.historicalMetrics.totalBlocksAtPoint, 1);

  const snap1 = ledger.getSnapshotAtBlock(1);
  assert.strictEqual(snap1.targetIndex, 1);
  assert.strictEqual(snap1.historicalMetrics.totalBlocksAtPoint, 2);
  assert(snap1.historicalMetrics.uniqueToolsCalled.includes('read_file'));

  // Out of bounds time-travel index check
  assert.throws(() => ledger.getSnapshotAtBlock(999), /out of bounds/);

  // 5. Single block restoration
  const restoredSingle = ledger.restoreChain(2);
  assert.strictEqual(restoredSingle, true, 'restoreChain(2) should return true');

  const healedVerify = ledger.verify();
  assert(healedVerify.valid, 'Ledger must be valid after block #2 is restored');
  const healedReport = ledger.locateTamper();
  assert(healedReport.intact, 'locateTamper must report intact: true after restoration');

  // 6. Multi-block tamper and restoreAll()
  ledger.tamper(1, { spoofed: 'b1' });
  ledger.tamper(3, { spoofed: 'b3' });
  assert(!ledger.verify().valid, 'Chain must be invalid with multiple tampered blocks');

  const restoreAllResult = ledger.restoreAll();
  assert.strictEqual(restoreAllResult.restoredCount, 2, 'Should restore both tampered blocks');
  assert(restoreAllResult.verification.valid, 'Chain must be pristine after restoreAll()');

  console.log('✅ Time-Travel Forensics & Tamper Localization: All 6 test cases passed!');
}

module.exports = { runForensicsTests };

if (require.main === module) {
  runForensicsTests();
}
