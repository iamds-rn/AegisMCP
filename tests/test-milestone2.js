/**
 * AegisMCP - Milestone 2 Dedicated Automated Unit & Stress Test Suite
 *
 * Verifies:
 * 1. Sliding-Window Token Bucket Rate Limiter in src/firewall/engine.js
 *    - Token replenishment, sliding-window rolling request boundary, cost calculation,
 *      multi-key/tool isolation, error code -32003 (AEGIS_RATE_LIMIT_EXCEEDED).
 * 2. Deterministic Execution Timeout Mapping in src/protocol/proxy.js
 *    - Instance default timeout, per-request override, downstream timeout error mapping,
 *      clearance of timers, error code -32005 (AEGIS_TIMEOUT).
 * 3. High-Concurrency & Adversarial Stress
 *    - Flood rate-limiting bursts, concurrent timeout storms, mixed traffic, ledger cryptographic integrity.
 */

'use strict';

const assert = require('node:assert');
const http = require('node:http');
const { FirewallEngine, TokenBucketRateLimiter, MODES } = require('../src/firewall/engine');
const { AegisProxyServer } = require('../src/protocol/proxy');
const { ERROR_CODES, createRequest } = require('../src/protocol/jsonrpc');

function postJson(url, data) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const body = typeof data === 'string' ? data : JSON.stringify(data);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body)
        }
      },
      res => {
        let resBody = '';
        res.on('data', chunk => { resBody += chunk; });
        res.on('end', () => {
          try {
            resolve({ statusCode: res.statusCode, data: JSON.parse(resBody) });
          } catch {
            resolve({ statusCode: res.statusCode, raw: resBody });
          }
        });
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let resBody = '';
      res.on('data', chunk => { resBody += chunk; });
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, data: JSON.parse(resBody) });
        } catch {
          resolve({ statusCode: res.statusCode, raw: resBody });
        }
      });
    }).on('error', reject);
  });
}

// =========================================================================
// SECTION 1: TokenBucketRateLimiter Unit Tests
// =========================================================================
function testTokenBucketRateLimiterUnit() {
  console.log('  [Section 1] TokenBucketRateLimiter Algorithmic Unit Tests...');

  let virtualTime = 1000000;
  const timeProvider = () => virtualTime;

  // 1.1 Burst capacity and exhaustion
  const limiter = new TokenBucketRateLimiter({
    capacity: 5,
    refillRate: 5,
    windowMs: 1000,
    timeProvider
  });

  for (let i = 0; i < 5; i++) {
    const res = limiter.consume('tool_a', 1);
    assert.strictEqual(res.allowed, true, `Consumption ${i + 1} should be allowed`);
    assert.strictEqual(res.remaining, 4 - i, `Remaining tokens should be ${4 - i}`);
  }

  // 6th consumption should be rejected
  const rejected = limiter.consume('tool_a', 1);
  assert.strictEqual(rejected.allowed, false, '6th consumption must be rejected');
  assert.strictEqual(rejected.remaining, 0, 'Remaining tokens should be 0');
  assert(rejected.retryAfterMs > 0, `retryAfterMs should be > 0, got ${rejected.retryAfterMs}`);
  assert.strictEqual(rejected.limit, 5);

  // 1.2 Time-based token replenishment
  virtualTime += 400; // 400ms elapsed -> (400 * 5) / 1000 = 2 tokens replenished
  const resReplenished1 = limiter.consume('tool_a', 1);
  assert.strictEqual(resReplenished1.allowed, true, 'Should allow request after 400ms replenishment');
  const resReplenished2 = limiter.consume('tool_a', 1);
  assert.strictEqual(resReplenished2.allowed, true, 'Should allow 2nd request from replenishment');
  const resReplenished3 = limiter.consume('tool_a', 1);
  assert.strictEqual(resReplenished3.allowed, false, 'Should reject 3rd request (exceeded replenishment)');

  // 1.3 Full window expiration restores all tokens
  virtualTime += 1001; // Window completely rolls over
  const checkState = limiter.check('tool_a');
  assert.strictEqual(checkState.remaining, 5, 'Full capacity should be available after window roll');

  // 1.4 Variable token cost
  const resCost = limiter.consume('tool_a', 3);
  assert.strictEqual(resCost.allowed, true);
  assert.strictEqual(resCost.remaining, 2);

  const resOverCost = limiter.consume('tool_a', 10);
  assert.strictEqual(resOverCost.allowed, false, 'Cost exceeding capacity must be rejected');

  // 1.5 Multi-tool isolation
  const resToolB = limiter.consume('tool_b', 1);
  assert.strictEqual(resToolB.allowed, true, 'tool_b has independent bucket and should succeed');

  // 1.6 Custom tool limits
  const customLimiter = new TokenBucketRateLimiter({
    capacity: 10,
    toolLimits: {
      strict_tool: { capacity: 2, refillRate: 2, windowMs: 1000 }
    },
    timeProvider
  });
  assert.strictEqual(customLimiter.consume('strict_tool', 1).allowed, true);
  assert.strictEqual(customLimiter.consume('strict_tool', 1).allowed, true);
  assert.strictEqual(customLimiter.consume('strict_tool', 1).allowed, false, 'strict_tool exceeds custom limit of 2');
  assert.strictEqual(customLimiter.consume('normal_tool', 1).allowed, true, 'normal_tool uses default capacity 10');

  // 1.7 Reset & Prune
  customLimiter.reset('strict_tool');
  assert.strictEqual(customLimiter.consume('strict_tool', 1).allowed, true, 'strict_tool works after reset');
  customLimiter.prune(0); // Prune all empty/old buckets

  console.log('    ✔ TokenBucketRateLimiter Unit Tests PASSED');
}

// =========================================================================
// SECTION 2: FirewallEngine Rate Limiting Integration Tests
// =========================================================================
function testFirewallRateLimitIntegration() {
  console.log('  [Section 2] FirewallEngine Rate Limiting & Mode Integration Tests...');

  let virtualTime = 500000;
  const timeProvider = () => virtualTime;

  // 2.1 ENFORCE Mode Block & -32003 Error
  const firewall = new FirewallEngine({
    mode: MODES.ENFORCE,
    rateLimit: {
      capacity: 2,
      refillRate: 2,
      windowMs: 1000,
      timeProvider
    }
  });

  const res1 = firewall.evaluate('read_file', { path: '/workspace/test.txt' }, 'req-1');
  assert.strictEqual(res1.allowed, true, 'Call 1 should pass');
  assert.strictEqual(res1.blocked, false);

  const res2 = firewall.evaluate('read_file', { path: '/workspace/test.txt' }, 'req-2');
  assert.strictEqual(res2.allowed, true, 'Call 2 should pass');

  // 3rd call exceeds rate limit
  const res3 = firewall.evaluate('read_file', { path: '/workspace/test.txt' }, 'req-3');
  assert.strictEqual(res3.allowed, false, 'Call 3 must be blocked');
  assert.strictEqual(res3.blocked, true, 'Call 3 blocked flag must be true');
  assert.strictEqual(res3.rateLimited, true, 'Call 3 rateLimited flag must be true');
  assert.strictEqual(res3.jsonrpcError.error.code, ERROR_CODES.AEGIS_RATE_LIMIT_EXCEEDED, 'Must return -32003');
  assert.strictEqual(res3.jsonrpcError.error.code, -32003, 'Must match standard -32003 code');
  assert.strictEqual(res3.jsonrpcError.id, 'req-3', 'Request ID must be preserved');
  assert.strictEqual(res3.jsonrpcError.error.data.ruleId, 'RATE-LIMIT');
  assert.strictEqual(res3.jsonrpcError.error.data.limit, 2);
  assert(res3.jsonrpcError.error.data.retryAfterMs > 0);

  // Telemetry assertions
  assert.strictEqual(firewall.stats.totalRateLimited, 1);
  assert.strictEqual(firewall.stats.totalBlocked, 1);
  const alerts = firewall.getRecentAlerts();
  assert(alerts.length > 0);
  assert.strictEqual(alerts[0].ruleId, 'RATE-LIMIT');
  assert.strictEqual(alerts[0].severity, 'HIGH');

  // 2.2 AUDIT_ONLY Mode allows through but flags
  firewall.setMode(MODES.AUDIT_ONLY);
  const resAudit = firewall.evaluate('read_file', { path: '/workspace/test.txt' }, 'req-4');
  assert.strictEqual(resAudit.allowed, true, 'AUDIT_ONLY mode must allow request');
  assert.strictEqual(resAudit.blocked, false);
  assert.strictEqual(resAudit.audited, true);
  assert.strictEqual(resAudit.rateLimited, true);
  assert.strictEqual(resAudit.jsonrpcError, undefined);

  // 2.3 SANITIZE Mode blocks rate limiting (rate limiting cannot be sanitized)
  firewall.setMode(MODES.SANITIZE);
  const resSanitize = firewall.evaluate('read_file', { path: '/workspace/test.txt' }, 'req-5');
  assert.strictEqual(resSanitize.allowed, false, 'SANITIZE mode must block rate limit breach');
  assert.strictEqual(resSanitize.blocked, true);
  assert.strictEqual(resSanitize.jsonrpcError.error.code, -32003);

  // 2.4 Dynamic setRateLimit reconfiguration
  firewall.setRateLimit({ capacity: 10, refillRate: 10, windowMs: 1000 });
  const resReconfigured = firewall.evaluate('read_file', { path: '/workspace/test.txt' }, 'req-6');
  assert.strictEqual(resReconfigured.allowed, true, 'Should allow after capacity expansion');

  firewall.setRateLimit(false); // disable
  assert.strictEqual(firewall.rateLimiter.enabled, false);

  console.log('    ✔ FirewallEngine Rate Limiting Integration Tests PASSED');
}

// =========================================================================
// SECTION 3: Proxy Server Rate Limiting & -32003 HTTP Protocol Tests
// =========================================================================
async function testProxyRateLimitHttpAndLedger() {
  console.log('  [Section 3] Proxy Gateway HTTP Conformance & Audit Ledger (-32003)...');

  const proxy = new AegisProxyServer({
    rateLimit: {
      capacity: 3,
      refillRate: 3,
      windowMs: 2000
    }
  });
  await proxy.startHttp(0);
  const port = proxy.port;
  const rpcUrl = `http://localhost:${port}/rpc`;

  try {
    // 3.1 First 3 calls succeed
    for (let i = 1; i <= 3; i++) {
      const res = await postJson(rpcUrl, createRequest('tools/call', {
        name: 'virtual_filesystem__read_file',
        arguments: { path: '/workspace/notes.txt' }
      }, `rl-req-${i}`));

      assert.strictEqual(res.statusCode, 200, 'HTTP status must be 200');
      assert(res.data.result, `Request ${i} must succeed with result`);
      assert(!res.data.error, `Request ${i} must not have error`);
    }

    // 3.2 4th call exceeded rate limit
    const resBlocked = await postJson(rpcUrl, createRequest('tools/call', {
      name: 'virtual_filesystem__read_file',
      arguments: { path: '/workspace/notes.txt' }
    }, 'rl-req-4'));

    assert.strictEqual(resBlocked.statusCode, 200, 'JSON-RPC errors return HTTP 200');
    assert(resBlocked.data.error, 'Must contain JSON-RPC error');
    assert.strictEqual(resBlocked.data.error.code, ERROR_CODES.AEGIS_RATE_LIMIT_EXCEEDED);
    assert.strictEqual(resBlocked.data.error.code, -32003, 'Must match standard -32003 error code');
    assert.strictEqual(resBlocked.data.id, 'rl-req-4');
    assert(resBlocked.data.error.message.includes('Rate Limit'));
    assert.strictEqual(resBlocked.data.error.data.ruleId, 'RATE-LIMIT');
    assert.strictEqual(resBlocked.data.error.data.limit, 3);
    assert(resBlocked.data.error.data.retryAfterMs > 0);

    // 3.3 Cryptographic Audit Ledger Verification
    const ledgerVerify = proxy.ledger.verify();
    assert.strictEqual(ledgerVerify.valid, true, 'Merkle chain must be valid');
    const recentBlocks = proxy.ledger.getRecentBlocks(10);
    const rateBlock = recentBlocks.find(b => (b.event && b.event.type === 'RATE_LIMIT_EXCEEDED') || b.eventType === 'RATE_LIMIT_EXCEEDED');
    assert(rateBlock, 'Audit ledger must contain a RATE_LIMIT_EXCEEDED event block');
    assert.strictEqual(rateBlock.event.tool, 'read_file');
    assert.strictEqual(rateBlock.event.id, 'rl-req-4');

    // 3.4 REST Rate Limit Management Endpoints
    const getRl = await getJson(`http://localhost:${port}/api/firewall/ratelimit`);
    assert.strictEqual(getRl.statusCode, 200);
    assert.strictEqual(getRl.data.enabled, true);
    assert.strictEqual(getRl.data.defaultCapacity, 3);

    const postRl = await postJson(`http://localhost:${port}/api/firewall/ratelimit`, {
      capacity: 50,
      refillRate: 50,
      windowMs: 5000
    });
    assert.strictEqual(postRl.statusCode, 200);
    assert.strictEqual(postRl.data.success, true);
    assert.strictEqual(postRl.data.rateLimiter.defaultCapacity, 50);

    console.log('    ✔ Proxy Gateway HTTP Conformance & Audit Ledger (-32003) PASSED');
  } finally {
    proxy.stop();
  }
}

// =========================================================================
// SECTION 4: Deterministic Tool Execution Timeout & -32005 Protocol Tests
// =========================================================================
async function testProxyDeterministicTimeout() {
  console.log('  [Section 4] Deterministic Tool Execution Timeout Mapping (-32005)...');

  const proxy = new AegisProxyServer({
    toolTimeoutMs: 60 // 60ms timeout default
  });
  await proxy.startHttp(0);
  const port = proxy.port;
  const rpcUrl = `http://localhost:${port}/rpc`;

  try {
    // 4.1 Server-level toolTimeoutMs enforcement
    const slowCall = await postJson(rpcUrl, createRequest('tools/call', {
      name: 'virtual_http_simulator__fetch_url',
      arguments: {
        url: 'https://example.com/api',
        delayMs: 200 // 200ms exceeds 60ms threshold
      }
    }, 'timeout-req-1'));

    assert.strictEqual(slowCall.statusCode, 200, 'JSON-RPC error returns HTTP 200');
    assert(slowCall.data.error, 'Must return JSON-RPC error');
    assert.strictEqual(slowCall.data.error.code, ERROR_CODES.AEGIS_TIMEOUT);
    assert.strictEqual(slowCall.data.error.code, -32005, 'Must match standard -32005 error code');
    assert.strictEqual(slowCall.data.id, 'timeout-req-1');
    assert(slowCall.data.error.message.includes('timed out'));
    assert.strictEqual(slowCall.data.error.data.timeoutMs, 60);
    assert.strictEqual(slowCall.data.error.data.tool, 'fetch_url');

    // 4.2 Per-request timeout override via _timeoutMs
    const overrideTimeout = await postJson(rpcUrl, createRequest('tools/call', {
      name: 'virtual_http_simulator__fetch_url',
      arguments: {
        url: 'https://example.com/api',
        delayMs: 120,
        _timeoutMs: 30 // Per-request override of 30ms
      }
    }, 'timeout-req-2'));

    assert.strictEqual(overrideTimeout.data.error.code, -32005, 'Must trigger -32005 on per-request timeout');
    assert.strictEqual(overrideTimeout.data.error.data.timeoutMs, 30, 'Error data must report overridden timeout');

    // 4.3 Fast tool call succeeds within timeout
    const fastCall = await postJson(rpcUrl, createRequest('tools/call', {
      name: 'virtual_http_simulator__fetch_url',
      arguments: {
        url: 'https://example.com/api',
        delayMs: 5
      }
    }, 'fast-req-1'));

    assert.strictEqual(fastCall.statusCode, 200);
    assert(fastCall.data.result, 'Fast call must succeed without timeout');
    assert(!fastCall.data.error);

    // 4.4 Downstream simulated timeout error mapping (ETIMEDOUT)
    const simulatedTimeout = await postJson(rpcUrl, createRequest('tools/call', {
      name: 'virtual_http_simulator__fetch_url',
      arguments: {
        url: 'https://example.com/api',
        simulateTimeout: true
      }
    }, 'timeout-sim-1'));

    assert.strictEqual(simulatedTimeout.data.error.code, -32005, 'ETIMEDOUT downstream must map to -32005');
    assert(simulatedTimeout.data.error.message.includes('ETIMEDOUT'));

    // 4.5 Tool execution non-timeout error distinction (-32603)
    const nonTimeoutErr = await postJson(rpcUrl, createRequest('tools/call', {
      name: 'virtual_filesystem__read_file',
      arguments: { path: '/non/existent/file.txt' }
    }, 'err-req-1'));

    assert.strictEqual(nonTimeoutErr.data.error.code, ERROR_CODES.INTERNAL_ERROR, 'Non-timeout error must return -32603');
    assert.strictEqual(nonTimeoutErr.data.error.code, -32603);

    // 4.6 Audit Ledger Records TOOL_CALL_TIMEOUT
    const ledgerVerify = proxy.ledger.verify();
    assert.strictEqual(ledgerVerify.valid, true, 'Ledger must remain cryptographically valid');
    const recentBlocks = proxy.ledger.getRecentBlocks(15);
    const timeoutBlocks = recentBlocks.filter(b => (b.event && b.event.type === 'TOOL_CALL_TIMEOUT') || b.eventType === 'TOOL_CALL_TIMEOUT');
    assert(timeoutBlocks.length >= 2, 'Audit ledger must log TOOL_CALL_TIMEOUT events');
    assert.strictEqual(timeoutBlocks[0].event.tool, 'fetch_url');

    console.log('    ✔ Deterministic Tool Execution Timeout Mapping (-32005) PASSED');
  } finally {
    proxy.stop();
  }
}

// =========================================================================
// SECTION 5: High-Concurrency & Adversarial Stress Tests
// =========================================================================
async function testHighConcurrencyStress() {
  console.log('  [Section 5] High-Concurrency Adversarial Rate-Limiting & Timeout Stress...');

  const proxy = new AegisProxyServer({
    toolTimeoutMs: 70,
    rateLimit: {
      capacity: 10,
      refillRate: 10,
      windowMs: 5000
    }
  });
  await proxy.startHttp(0);
  const port = proxy.port;
  const rpcUrl = `http://localhost:${port}/rpc`;

  try {
    // 5.1 Concurrency Burst 1: 50 parallel requests against rate limit of 10
    const BURST_COUNT = 50;
    const burstPromises = [];
    for (let i = 0; i < BURST_COUNT; i++) {
      burstPromises.push(
        postJson(rpcUrl, createRequest('tools/call', {
          name: 'virtual_filesystem__read_file',
          arguments: { path: '/workspace/notes.txt' }
        }, `burst-rl-${i}`))
      );
    }

    const burstResponses = await Promise.all(burstPromises);
    let successCount = 0;
    let rateLimitedCount = 0;

    for (const r of burstResponses) {
      assert.strictEqual(r.statusCode, 200, 'All JSON-RPC calls return HTTP 200');
      if (r.data.result) {
        successCount++;
      } else if (r.data.error && r.data.error.code === -32003) {
        rateLimitedCount++;
      }
    }

    assert.strictEqual(successCount, 10, `Expected exactly 10 requests to pass capacity, got ${successCount}`);
    assert.strictEqual(rateLimitedCount, 40, `Expected exactly 40 requests to be rate-limited (-32003), got ${rateLimitedCount}`);
    console.log(`    ⚡ Burst 1: 50 concurrent requests -> ${successCount} passed, ${rateLimitedCount} rejected (-32003) cleanly.`);

    // 5.2 Concurrency Burst 2: 30 parallel requests triggering timeouts
    const TIMEOUT_BURST = 30;
    const timeoutPromises = [];
    for (let i = 0; i < TIMEOUT_BURST; i++) {
      timeoutPromises.push(
        postJson(rpcUrl, createRequest('tools/call', {
          name: 'virtual_http_simulator__fetch_url',
          arguments: {
            url: `https://example.com/stream-${i}`,
            delayMs: 180, // Exceeds 70ms threshold
            _key: `client-${i}` // Independent rate limit key so rate limiter doesn't drop them first
          }
        }, `burst-to-${i}`))
      );
    }

    const timeoutResponses = await Promise.all(timeoutPromises);
    let timeoutCount = 0;
    for (const r of timeoutResponses) {
      assert.strictEqual(r.statusCode, 200);
      if (r.data.error && r.data.error.code === -32005) {
        timeoutCount++;
      }
    }

    assert.strictEqual(timeoutCount, TIMEOUT_BURST, `All ${TIMEOUT_BURST} parallel slow requests must return -32005`);
    console.log(`    ⚡ Burst 2: ${TIMEOUT_BURST} concurrent slow requests -> ${timeoutCount} timed out (-32005) deterministically.`);

    // 5.3 Post-Stress Gateway Health & Cryptographic Integrity
    const health = await getJson(`http://localhost:${port}/health`);
    assert.strictEqual(health.statusCode, 200);
    assert.strictEqual(health.data.status, 'healthy');

    const ledgerVerify = proxy.ledger.verify();
    assert.strictEqual(ledgerVerify.valid, true, 'SHA-256 Merkle chain must remain 100% valid under stress');
    console.log(`    ⚡ Cryptographic Integrity: Head hash ${ledgerVerify.headHash.slice(0, 16)}... with ${ledgerVerify.verifiedBlocks} verified blocks.`);

    console.log('    ✔ High-Concurrency Adversarial Rate-Limiting & Timeout Stress PASSED');
  } finally {
    proxy.stop();
  }
}

// =========================================================================
// RUN ALL TESTS
// =========================================================================
async function runMilestone2Tests() {
  console.log('🧪 Testing Milestone 2 Rate Limiter (-32003) & Execution Timeout (-32005)...');
  testTokenBucketRateLimiterUnit();
  testFirewallRateLimitIntegration();
  await testProxyRateLimitHttpAndLedger();
  await testProxyDeterministicTimeout();
  await testHighConcurrencyStress();
  console.log('✅ Milestone 2 Features: All unit, integration, and stress tests passed!\n');
}

if (require.main === module) {
  runMilestone2Tests().catch(err => {
    console.error('❌ Milestone 2 Test Suite Failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runMilestone2Tests
};
