/**
 * End-to-End Protocol and Gateway Integration Tests
 */

'use strict';

const assert = require('node:assert');
const http = require('node:http');
const { AegisProxyServer } = require('../src/protocol/proxy');
const { createRequest } = require('../src/protocol/jsonrpc');

function postJson(url, data) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const body = JSON.stringify(data);
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

async function runE2ETests() {
  console.log('🧪 Testing End-to-End Protocol & HTTP Gateway Server...');

  const testPort = 3399;
  const proxy = new AegisProxyServer({ port: testPort });
  await proxy.startHttp(testPort);

  try {
    const baseUrl = `http://localhost:${testPort}`;

    // 1. Health check
    const health = await getJson(`${baseUrl}/health`);
    assert.strictEqual(health.statusCode, 200);
    assert.strictEqual(health.data.status, 'healthy');

    // 2. Protocol Handshake: initialize
    const initReq = createRequest('initialize', { clientInfo: { name: 'TestClient', version: '1.0' } }, 1);
    const initRes = await postJson(`${baseUrl}/rpc`, initReq);
    assert.strictEqual(initRes.data.result.serverInfo.name, 'AegisMCP-Proxy');
    assert.strictEqual(initRes.data.result.capabilities.aegis.firewall, true);

    // 3. Tools Discovery: tools/list
    const listReq = createRequest('tools/list', {}, 2);
    const listRes = await postJson(`${baseUrl}/rpc`, listReq);
    assert(Array.isArray(listRes.data.result.tools));
    assert(listRes.data.result.tools.length >= 10);

    // 4. Safe Tool Call: tools/call
    const callSafeReq = createRequest('tools/call', {
      name: 'virtual_filesystem__read_file',
      arguments: { path: '/workspace/project.json' }
    }, 3);
    const callSafeRes = await postJson(`${baseUrl}/rpc`, callSafeReq);
    assert(callSafeRes.data.result.content[0].text.includes('AlphaPilot'));

    // 5. Malicious Tool Call Interception: Path Traversal
    const callAttackReq = createRequest('tools/call', {
      name: 'virtual_filesystem__read_file',
      arguments: { path: '../../../../etc/shadow' }
    }, 4);
    const callAttackRes = await postJson(`${baseUrl}/rpc`, callAttackReq);
    assert(callAttackRes.data.error, 'Malicious tool call must return an error response');
    assert.strictEqual(callAttackRes.data.error.code, -32001, 'Must return Aegis Policy Violation code -32001');
    assert(callAttackRes.data.error.message.includes('AegisMCP Security Firewall Block'));

    // 6. Stats API verification
    const statsRes = await getJson(`${baseUrl}/api/stats`);
    assert.strictEqual(statsRes.data.firewall.totalBlocked, 1);
    assert.strictEqual(statsRes.data.ledger.valid, true);

    // 7. Ledger Verification API
    const verifyRes = await getJson(`${baseUrl}/api/ledger/verify`);
    assert.strictEqual(verifyRes.data.valid, true);

    // 8. Fuzzer API endpoint
    const fuzzRes = await postJson(`${baseUrl}/api/fuzz`, {
      serverName: 'virtual_crypto',
      toolName: 'hash_sha256',
      withFirewall: true
    });
    assert.strictEqual(fuzzRes.statusCode, 200);
    assert.strictEqual(fuzzRes.data.toolName, 'hash_sha256');
    assert(['A+', 'A'].includes(fuzzRes.data.grade));

    // 9. Static Asset Path Traversal Immunity Test
    const traversalRes = await getJson(`${baseUrl}/../../package.json`);
    const bodyStr = typeof traversalRes.data === 'string' ? traversalRes.data : JSON.stringify(traversalRes.data || traversalRes.raw || '');
    assert(!bodyStr.includes('"name": "aegis-mcp"'), 'Static file server must NOT leak package.json via path traversal');

    // 10. Tools/call missing name parameter validation
    const invalidCallReq = createRequest('tools/call', {}, 5);
    const invalidCallRes = await postJson(`${baseUrl}/rpc`, invalidCallReq);
    assert(invalidCallRes.data.error, 'Calling tools/call without name must return error');
    assert.strictEqual(invalidCallRes.data.error.code, -32602, 'Should return -32602 INVALID_PARAMS');

    // 11. Exploit Payload Generator & Resilience Auditor API endpoint
    const exploitRes = await postJson(`${baseUrl}/api/firewall/exploit-audit`, {
      serverName: 'virtual_filesystem',
      toolName: 'read_file',
      withFirewall: true
    });
    assert.strictEqual(exploitRes.statusCode, 200);
    assert.strictEqual(exploitRes.data.grade, 'A+');
    assert.strictEqual(exploitRes.data.defenseScorePct, 100);
    assert(exploitRes.data.totalExploits >= 15);

    // 12. Cryptographic Ledger Forensics endpoint
    const forensicsRes = await getJson(`${baseUrl}/api/ledger/forensics`);
    assert.strictEqual(forensicsRes.statusCode, 200);
    assert.strictEqual(forensicsRes.data.intact, true);
    assert(forensicsRes.data.forensicSummary.includes('PRISTINE'));

    // 13. Client Configuration Generator endpoint
    const configRes = await getJson(`${baseUrl}/api/configs/claude`);
    assert.strictEqual(configRes.statusCode, 200);
    assert.strictEqual(configRes.data.name, 'Claude Desktop');
    assert(configRes.data.snippet);

    // 14. Firewall Rules API endpoint
    const rulesRes = await getJson(`${baseUrl}/api/firewall/rules`);
    assert.strictEqual(rulesRes.statusCode, 200);
    assert(Array.isArray(rulesRes.data.rules));
    assert(rulesRes.data.rules.length >= 9);

    // 15. Server Fleet endpoint
    const serversRes = await getJson(`${baseUrl}/api/servers`);
    assert.strictEqual(serversRes.statusCode, 200);
    assert(Array.isArray(serversRes.data.servers));
    assert(serversRes.data.servers.length >= 4);

    console.log('✅ End-to-End Protocol & Gateway: All 15 test cases passed!');
  } finally {
    proxy.stop();
  }
}

module.exports = { runE2ETests };

if (require.main === module) {
  runE2ETests().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
