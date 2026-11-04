/**
 * AegisMCP - MCP Protocol Proxy & Gateway Endpoints Integration Tests
 * Thoroughly verifies stdio, ping, notification absorption, resources/prompts, HTTP 413 DoS, and REST management endpoints.
 */

'use strict';

const assert = require('node:assert');
const http = require('node:http');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const { AegisProxyServer } = require('../src/protocol/proxy');
const { createRequest, createNotification } = require('../src/protocol/jsonrpc');

function postJson(url, data, customHeaders = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const body = typeof data === 'string' ? data : JSON.stringify(data);
    const headers = Object.assign(
      {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      },
      customHeaders
    );

    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: 'POST',
        headers
      },
      res => {
        let resBody = '';
        res.on('data', chunk => { resBody += chunk; });
        res.on('end', () => {
          try {
            resolve({ statusCode: res.statusCode, headers: res.headers, data: JSON.parse(resBody) });
          } catch {
            resolve({ statusCode: res.statusCode, headers: res.headers, raw: resBody });
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
          resolve({ statusCode: res.statusCode, headers: res.headers, data: JSON.parse(resBody) });
        } catch {
          resolve({ statusCode: res.statusCode, headers: res.headers, raw: resBody });
        }
      });
    }).on('error', reject);
  });
}

function sendOptions(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: 'OPTIONS'
      },
      res => {
        resolve({ statusCode: res.statusCode, headers: res.headers });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

async function runProxyEndpointsTests() {
  console.log('🧪 Testing MCP Proxy Gateway & Endpoints Conformance...');

  // Start proxy server on ephemeral port 0
  const proxy = new AegisProxyServer({ port: 0 });
  const server = await proxy.startHttp(0);
  const actualPort = server.address().port;
  const baseUrl = `http://localhost:${actualPort}`;

  try {
    // 1. MCP Protocol Ping Probe
    const pingReq = createRequest('ping', {}, 10);
    const pingRes = await postJson(`${baseUrl}/rpc`, pingReq);
    assert.strictEqual(pingRes.statusCode, 200, 'Ping request must return 200 OK');
    assert.strictEqual(pingRes.data.id, 10);
    assert.deepStrictEqual(pingRes.data.result, {}, 'Ping response must return empty object {}');

    // 2. MCP Resources Discovery Stub: resources/list
    const resourcesReq = createRequest('resources/list', {}, 11);
    const resourcesRes = await postJson(`${baseUrl}/rpc`, resourcesReq);
    assert.strictEqual(resourcesRes.statusCode, 200);
    assert.strictEqual(resourcesRes.data.id, 11);
    assert.deepStrictEqual(resourcesRes.data.result, { resources: [] }, 'resources/list must return { resources: [] }');

    // 3. MCP Prompts Discovery Stub: prompts/list
    const promptsReq = createRequest('prompts/list', {}, 12);
    const promptsRes = await postJson(`${baseUrl}/rpc`, promptsReq);
    assert.strictEqual(promptsRes.statusCode, 200);
    assert.strictEqual(promptsRes.data.id, 12);
    assert.deepStrictEqual(promptsRes.data.result, { prompts: [] }, 'prompts/list must return { prompts: [] }');

    // 4. HTTP Notification Absorption (/rpc)
    // Client sends notification with no id (e.g. notifications/initialized)
    const initNotif = createNotification('notifications/initialized', {});
    const notifRes = await postJson(`${baseUrl}/rpc`, initNotif);
    assert([200, 204].includes(notifRes.statusCode), 'Notifications must return HTTP 200 or 204');
    if (notifRes.data) {
      assert(!notifRes.data.error, 'Notification MUST NOT trigger an error response frame');
    }

    const cancelNotif = createNotification('notifications/cancelled', { requestId: 1 });
    const cancelRes = await postJson(`${baseUrl}/rpc`, cancelNotif);
    assert([200, 204].includes(cancelRes.statusCode));
    if (cancelRes.data) {
      assert(!cancelRes.data.error, 'Cancelled notification must not trigger an error response');
    }

    // 5. /mcp Route Alias Verification
    const mcpPingRes = await postJson(`${baseUrl}/mcp`, pingReq);
    assert.strictEqual(mcpPingRes.statusCode, 200);
    assert.deepStrictEqual(mcpPingRes.data.result, {});

    // 6. Unhandled Method Error Handling
    const unknownReq = createRequest('custom/unknownMethod', {}, 13);
    const unknownRes = await postJson(`${baseUrl}/rpc`, unknownReq);
    assert.strictEqual(unknownRes.statusCode, 200);
    assert(unknownRes.data.error, 'Unknown method must return JSON-RPC error');
    assert.strictEqual(unknownRes.data.error.code, -32601, 'Should return METHOD_NOT_FOUND code -32601');

    // 7. CORS Preflight (OPTIONS)
    const optionsRes = await sendOptions(`${baseUrl}/rpc`);
    assert.strictEqual(optionsRes.statusCode, 204);
    assert.strictEqual(optionsRes.headers['access-control-allow-origin'], '*');
    assert(optionsRes.headers['access-control-allow-methods'].includes('POST'));

    // 8. REST Endpoint: Merkle Ledger Proof Export
    const proofRes = await getJson(`${baseUrl}/api/ledger/proof`);
    assert.strictEqual(proofRes.statusCode, 200);
    assert(proofRes.data.headHash, 'Export proof must contain headHash');
    assert(Array.isArray(proofRes.data.blocks), 'Export proof must contain blocks array');

    // 9. REST Endpoint: Tamper Simulation & 1-Click Restoration
    const tamperRes = await postJson(`${baseUrl}/api/ledger/tamper`, { index: 1 });
    assert.strictEqual(tamperRes.statusCode, 200);
    assert.strictEqual(tamperRes.data.tamperedIndex, 1);

    const verifyTampered = await getJson(`${baseUrl}/api/ledger/verify`);
    assert.strictEqual(verifyTampered.data.valid, false, 'Ledger must be marked invalid after tamper simulation');

    const restoreRes = await postJson(`${baseUrl}/api/ledger/restore`, {});
    assert.strictEqual(restoreRes.statusCode, 200);

    const verifyRestored = await getJson(`${baseUrl}/api/ledger/verify`);
    assert.strictEqual(verifyRestored.data.valid, true, 'Ledger must be valid after restoration');

    // 10. REST Endpoint: Historical Block Snapshot
    const snapRes = await getJson(`${baseUrl}/api/ledger/snapshot/0`);
    assert.strictEqual(snapRes.statusCode, 200);
    assert.strictEqual(snapRes.data.targetIndex, 0, 'Snapshot at block 0 must return Genesis block');

    // 11. REST Endpoint: Firewall Rule Toggling
    const toggleOff = await postJson(`${baseUrl}/api/firewall/rules/toggle`, { ruleId: 'SEC-001' });
    assert.strictEqual(toggleOff.statusCode, 200);
    assert.strictEqual(toggleOff.data.enabled, false);

    const toggleOn = await postJson(`${baseUrl}/api/firewall/rules/toggle`, { ruleId: 'SEC-001' });
    assert.strictEqual(toggleOn.statusCode, 200);
    assert.strictEqual(toggleOn.data.enabled, true);

    // 12. REST Endpoint: Add Custom Rule
    const addRuleRes = await postJson(`${baseUrl}/api/firewall/rules/add`, {
      id: 'CUSTOM-TEST-01',
      name: 'Dynamic Test Injection Rule',
      pattern: 'malicious_test_marker'
    });
    assert.strictEqual(addRuleRes.statusCode, 200);
    assert.strictEqual(addRuleRes.data.success, true);

    // 13. REST Endpoint: Dynamic Rule Synthesis
    const synthRes = await postJson(`${baseUrl}/api/firewall/synthesize`, {
      pattern: 'aws_secret_key_[a-z0-9]+',
      signatureName: 'Test AWS Synth'
    });
    assert.strictEqual(synthRes.statusCode, 200);
    assert(Array.isArray(synthRes.data.rules));
    assert(synthRes.data.rules.length > 0);

    // 14. REST Endpoint: Visual DAG Pipeline Execution
    const pipelineRes = await postJson(`${baseUrl}/api/pipeline/run`, {
      id: 'test-pipeline',
      nodes: [
        {
          id: 'step1',
          server: 'virtual_crypto',
          tool: 'hash_sha256',
          params: { text: 'test-data-pipeline' }
        }
      ]
    });
    assert.strictEqual(pipelineRes.statusCode, 200);
    assert.strictEqual(pipelineRes.data.status, 'COMPLETED');
    assert.strictEqual(pipelineRes.data.stepsExecuted, 1);
    assert(pipelineRes.data.finalOutputs.step1);

    // 15. HTTP Gateway Streaming DoS Protection (HTTP 413)
    // Send request exceeding body limit (e.g. 1.1MB payload to default 1MB limit)
    const largePayload = JSON.stringify({
      jsonrpc: '2.0',
      id: 999,
      method: 'tools/call',
      params: {
        name: 'virtual_filesystem__write_file',
        arguments: { path: '/tmp/dos.txt', content: 'X'.repeat(1024 * 1024 + 1024) }
      }
    });

    let dosStatusCode = null;
    try {
      const dosRes = await postJson(`${baseUrl}/rpc`, largePayload);
      dosStatusCode = dosRes.statusCode;
    } catch (err) {
      // In event of immediate socket destruction, ECONNRESET or EPIPE is valid DoS termination
      if (err.code === 'ECONNRESET' || err.code === 'EPIPE') {
        dosStatusCode = 413;
      }
    }
    assert.strictEqual(dosStatusCode, 413, 'Oversized payload must be rejected with HTTP 413');

    // Verify gateway resilience: server must remain healthy after DoS attempt
    const healthCheckAfterDos = await getJson(`${baseUrl}/health`);
    assert.strictEqual(healthCheckAfterDos.statusCode, 200);
    assert.strictEqual(healthCheckAfterDos.data.status, 'healthy');

    // 16. Stdio Transport Supervision Test (Notification Absorption in stdio)
    await testStdioTransport();

    console.log('✅ MCP Proxy Gateway & Endpoints: All 16 conformance test cases passed!');
  } finally {
    proxy.stop();
  }
}

/**
 * Spawns AegisMCP CLI in stdio mode and verifies bidirectional framing and notification absorption.
 */
function testStdioTransport() {
  return new Promise((resolve, reject) => {
    const cliPath = path.resolve(__dirname, '../bin/aegis-mcp.js');
    const child = spawn(process.execPath, [cliPath, '--stdio'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    const receivedLines = [];
    const rl = readline.createInterface({ input: child.stdout, terminal: false });

    rl.on('line', line => {
      if (line.trim()) {
        try {
          receivedLines.push(JSON.parse(line.trim()));
        } catch {
          // Non-JSON output
        }
      }
    });

    child.on('error', reject);

    // Send initialize request
    const initReq = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { clientInfo: { name: 'StdioTestClient', version: '1.0' } }
    });
    child.stdin.write(initReq + '\n');

    // Send notifications/initialized (MUST BE ABSORBED SILENTLY - ZERO OUTPUT)
    const initNotif = JSON.stringify({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
      params: {}
    });
    child.stdin.write(initNotif + '\n');

    // Send ping request (id: 2)
    const pingReq = JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'ping'
    });
    child.stdin.write(pingReq + '\n');

    // Wait 250ms for lines to process
    setTimeout(() => {
      try {
        child.kill();

        // Must receive exactly 2 responses: initialize (id: 1) and ping (id: 2)
        assert.strictEqual(receivedLines.length, 2, `Expected 2 responses over stdio, got ${receivedLines.length}`);
        assert.strictEqual(receivedLines[0].id, 1, 'First response must be for initialize');
        assert.strictEqual(receivedLines[0].result.serverInfo.name, 'AegisMCP-Proxy');

        assert.strictEqual(receivedLines[1].id, 2, 'Second response must be for ping');
        assert.deepStrictEqual(receivedLines[1].result, {});

        resolve();
      } catch (err) {
        reject(err);
      }
    }, 250);
  });
}

module.exports = { runProxyEndpointsTests };

if (require.main === module) {
  runProxyEndpointsTests().catch(err => {
    console.error('Proxy Endpoints Test Failed:', err);
    process.exit(1);
  });
}
