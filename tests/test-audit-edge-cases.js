/**
 * AegisMCP - Deep Code Audit & Bug Hunter Reproduction Suite
 * Verifies edge-case defects, async unhandled rejections, socket cleanup, and null dereference resilience.
 */

'use strict';

const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const { AegisProxyServer } = require('../src/protocol/proxy');
const { AuditLedger } = require('../src/ledger/auditLedger');
const { VirtualMemoryServer } = require('../src/servers/virtualHub');
const { ClientConfigGenerator } = require('../src/protocol/configGenerator');
const { TokenBucketRateLimiter } = require('../src/firewall/engine');
const { ERROR_CODES } = require('../src/protocol/jsonrpc');

async function runEdgeCaseAuditTests() {
  console.log('🧪 Testing Deep Audit Edge Cases & Defect Reproductions...');

  // -------------------------------------------------------------
  // Defect 1: HTTP Gateway Unhandled Promise Rejection on Malformed URL / Host
  // -------------------------------------------------------------
  console.log('  [Defect 1] Testing Gateway immunity against malformed Host / URL headers...');
  const proxy = new AegisProxyServer({ port: 0 });
  const server = await proxy.startHttp(0);
  const port = server.address().port;

  let unhandledRejectionCaught = null;
  const onUnhandled = (err) => {
    unhandledRejectionCaught = err;
  };
  process.on('unhandledRejection', onUnhandled);

  try {
    // Send HTTP request with malformed Host header that causes new URL() to throw
    await new Promise((resolve) => {
      const client = net.connect({ port, host: '127.0.0.1' }, () => {
        client.write('GET /health HTTP/1.1\r\nHost: [invalid-host\r\n\r\n');
        setTimeout(() => {
          client.destroy();
          resolve();
        }, 50);
      });
      client.on('error', () => resolve());
    });

    await new Promise(r => setTimeout(r, 100));
    assert.strictEqual(
      unhandledRejectionCaught,
      null,
      `Gateway must not produce unhandled promise rejection on malformed host, caught: ${unhandledRejectionCaught && unhandledRejectionCaught.message}`
    );
  } finally {
    process.removeListener('unhandledRejection', onUnhandled);
    proxy.stop();
  }

  // -------------------------------------------------------------
  // Defect 2: handleJsonRpc null / primitive argument safety
  // -------------------------------------------------------------
  console.log('  [Defect 2] Testing handleJsonRpc robustness on null and non-object inputs...');
  const proxy2 = new AegisProxyServer();
  const nullResult = await proxy2.handleJsonRpc(null);
  assert(nullResult && nullResult.error, 'handleJsonRpc(null) must return JSON-RPC error');
  assert.strictEqual(nullResult.error.code, ERROR_CODES.INVALID_REQUEST);

  const stringResult = await proxy2.handleJsonRpc('raw-string-request');
  assert(stringResult && stringResult.error, 'handleJsonRpc(string) must return JSON-RPC error');
  assert.strictEqual(stringResult.error.code, ERROR_CODES.INVALID_REQUEST);

  const arrayResult = await proxy2.handleJsonRpc([1, 2, 3]);
  assert(arrayResult && arrayResult.error, 'handleJsonRpc(array) must return JSON-RPC error');
  assert.strictEqual(arrayResult.error.code, ERROR_CODES.INVALID_REQUEST);

  // -------------------------------------------------------------
  // Defect 3: AuditLedger null / primitive tampered event safety
  // -------------------------------------------------------------
  console.log('  [Defect 3] Testing AuditLedger forensics & exportProof on null / primitive tampered events...');
  const ledger = new AuditLedger();
  ledger.append('STEP_1', { data: 'pristine' });
  ledger.append('STEP_2', { data: 'pristine_2' });

  // Tamper with null
  ledger.tamper(1, null);

  const forensicsNull = ledger.locateTamper();
  assert.strictEqual(forensicsNull.intact, false);
  assert.strictEqual(forensicsNull.tamperedIndex, 1);

  const snapNull = ledger.getSnapshotAtBlock(1);
  assert.strictEqual(snapNull.targetIndex, 1);

  const proofNull = ledger.exportProof();
  assert.strictEqual(proofNull.integrityStatus, 'COMPROMISED');

  // Restore and verify pristine
  assert(ledger.restoreChain(1));
  assert(ledger.verify().valid);

  // Tamper with primitive string
  ledger.tamper(2, 'tampered string literal');
  const forensicsStr = ledger.locateTamper();
  assert.strictEqual(forensicsStr.intact, false);
  assert.strictEqual(forensicsStr.tamperedIndex, 2);
  assert(ledger.restoreChain(2));
  assert(ledger.verify().valid);

  // -------------------------------------------------------------
  // Defect 4: VirtualMemoryServer search_keys with non-string tags
  // -------------------------------------------------------------
  console.log('  [Defect 4] Testing VirtualMemoryServer with non-string tags in search_keys...');
  const memServer = new VirtualMemoryServer();
  await memServer.callTool('set_key', {
    key: 'numeric_tags_key',
    value: { data: 'test' },
    tags: [100, 200, true]
  });
  const searchResult = await memServer.callTool('search_keys', { query: '100' });
  assert(searchResult.content[0].text.includes('numeric_tags_key'), 'search_keys must find key with numeric tags');

  // -------------------------------------------------------------
  // Defect 5: ClientConfigGenerator.generate null / non-string type guard
  // -------------------------------------------------------------
  console.log('  [Defect 5] Testing ClientConfigGenerator argument type guard...');
  assert.throws(() => ClientConfigGenerator.generate(null), /Client type must be a valid string/);
  assert.throws(() => ClientConfigGenerator.generate(12345), /Client type must be a valid string/);
  assert.throws(() => ClientConfigGenerator.generate(undefined), /Client type must be a valid string/);

  // -------------------------------------------------------------
  // Defect 6: TokenBucketRateLimiter Auto-Pruning Under High Key Cardinality
  // -------------------------------------------------------------
  console.log('  [Defect 6] Testing TokenBucketRateLimiter automatic memory bounding...');
  let now = 1000000;
  const limiter = new TokenBucketRateLimiter({
    capacity: 10,
    refillRate: 10,
    windowMs: 1000,
    timeProvider: () => now
  });

  // Create 5500 distinct buckets older than maxAgeMs to trigger auto-prune
  for (let i = 0; i < 5200; i++) {
    limiter.consume(`client_${i}`, 1, now);
  }

  // Advance time past default maxAgeMs (300000ms = 5min)
  now += 400000;

  // Next bucket creation must trigger auto-prune and reduce activeBuckets
  limiter.consume('trigger_client', 1, now);
  assert(limiter.buckets.size <= 5000, `Active buckets must be bounded <= 5000, got ${limiter.buckets.size}`);

  console.log('✅ Deep Audit Edge Cases & Defect Reproductions: All tests passed!');
}

module.exports = { runEdgeCaseAuditTests };

if (require.main === module) {
  runEdgeCaseAuditTests().catch(err => {
    console.error('Audit Test Suite Failed:', err);
    process.exit(1);
  });
}
