/**
 * Tests for AegisMCP External Server stdio Proxy Tunneling
 */

'use strict';

const assert = require('node:assert');
const path = require('node:path');
const { ExternalProcessServer } = require('../src/servers/externalProcessServer');
const { VirtualHub } = require('../src/servers/virtualHub');
const { FirewallEngine, MODES } = require('../src/firewall/engine');

// Inline mock MCP server script that listens on stdin and responds over stdout
const MOCK_SERVER_SCRIPT = `
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    const msg = JSON.parse(trimmed);
    const { id, method, params } = msg;

    if (method === 'initialize') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'mock-external-mcp', version: '2.1.0' }
        }
      }) + '\\n');
      return;
    }

    if (method === 'tools/list') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            {
              name: 'external_fetch_data',
              description: 'Fetches mock remote record',
              inputSchema: {
                type: 'object',
                properties: { query: { type: 'string' } },
                required: ['query']
              }
            }
          ]
        }
      }) + '\\n');
      return;
    }

    if (method === 'tools/call') {
      const q = (params && params.arguments) ? params.arguments.query : 'default';
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: 'External query result: ' + q }]
        }
      }) + '\\n');
      return;
    }
  } catch (err) {
    // Ignore parse error
  }
});
`;

async function runExternalServerTests() {
  console.log('🧪 Testing External MCP Server stdio Proxy Tunneling...');

  const mockServerPath = path.join(__dirname, 'mock-mcp-server.js');

  // 1. Spawning ExternalProcessServer
  const extServer = new ExternalProcessServer({
    name: 'ext_mock',
    command: 'node',
    args: [mockServerPath]
  });

  await extServer.start();
  assert.strictEqual(extServer.status, 'CONNECTED', 'Server status should be CONNECTED');
  assert.strictEqual(extServer.isReady, true, 'Server should be marked ready');

  // 2. Dynamic Tool Discovery
  const tools = extServer.getTools();
  assert.strictEqual(tools.length, 1, 'Should discover 1 tool from external server');
  assert.strictEqual(tools[0].name, 'external_fetch_data');
  assert.strictEqual(tools[0].serverName, 'ext_mock');

  // 3. Direct Tool Call to External Process
  const callRes = await extServer.callTool('external_fetch_data', { query: 'test_query_123' });
  assert(callRes.content[0].text.includes('test_query_123'), 'Result should reflect executed query');

  // 4. Registration into VirtualHub
  const hub = new VirtualHub();
  hub.registerServer(extServer);

  const hubServers = hub.listServers();
  const mockHubEntry = hubServers.find(s => s.name === 'ext_mock');
  assert(mockHubEntry, 'External server should be listed in hub');
  assert.strictEqual(mockHubEntry.isExternal, true, 'isExternal flag should be true');

  // 5. Zero-Trust Firewall Protection on External Tool
  const firewall = new FirewallEngine({ mode: MODES.ENFORCE });

  // Adversarial call targeting external tool (Directory traversal / Sensitive path)
  const maliciousArgs = { query: '../../../../etc/shadow' };
  const evalResult = firewall.evaluate('external_fetch_data', maliciousArgs);

  assert(evalResult.blocked, 'Aegis Firewall MUST block traversal attempt before it reaches external process');
  assert.strictEqual(evalResult.violation.ruleId, 'SEC-001');

  // Benign call targeting external tool
  const benignArgs = { query: 'legitimate_search_term' };
  const benignEval = firewall.evaluate('external_fetch_data', benignArgs);
  assert(benignEval.allowed, 'Clean argument must be allowed');

  const safeResult = await hub.executeTool('ext_mock', 'external_fetch_data', benignArgs);
  assert(safeResult.content[0].text.includes('legitimate_search_term'));

  // 6. Clean Shutdown of External Child Process
  extServer.stop();
  assert.strictEqual(extServer.status, 'STOPPED');
  assert.strictEqual(extServer.isReady, false);

  hub.shutdownAll();

  console.log('✅ External MCP Server stdio Proxy Tunneling: All 6 test cases passed!');
}

module.exports = { runExternalServerTests };

if (require.main === module) {
  runExternalServerTests().catch(err => {
    console.error('External Server Test Failed:', err);
    process.exit(1);
  });
}
