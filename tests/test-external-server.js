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

  // 7. Tokenize Command Unit Tests
  const { tokenizeCommand } = require('../src/servers/externalProcessServer');
  const tokens1 = tokenizeCommand('npx -y @modelcontextprotocol/server-filesystem "/path with spaces/data"');
  assert.deepStrictEqual(tokens1, ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/path with spaces/data']);

  const tokens2 = tokenizeCommand("node server.js 'single quoted string' --flag");
  assert.deepStrictEqual(tokens2, ['node', 'server.js', 'single quoted string', '--flag']);

  // 8. Spawn external server using single command string with quoted args
  const quotedExt = new ExternalProcessServer({
    name: 'ext_quoted',
    command: `node "${mockServerPath}"`
  });
  await quotedExt.start();
  assert.strictEqual(quotedExt.status, 'CONNECTED');
  const qTools = quotedExt.getTools();
  assert.strictEqual(qTools.length, 1);
  quotedExt.stop();

  // 9. Empty Quote Tokenization Preservation
  const tokensEmpty = tokenizeCommand('node script.js "" --flag \'\'');
  assert.deepStrictEqual(tokensEmpty, ['node', 'script.js', '', '--flag', ''], 'Empty quotes must be preserved as empty string tokens');

  // 10. Auto-Restart on Unexpected Exit (SIGKILL)
  const restartServer = new ExternalProcessServer({
    name: 'ext_restart_test',
    command: 'node',
    args: [mockServerPath],
    autoRestart: true,
    maxRetries: 3,
    restartDelayMs: 50
  });
  await restartServer.start();
  assert.strictEqual(restartServer.status, 'CONNECTED');

  const proc = restartServer.process;
  assert(proc, 'Child process must exist');

  // Trigger unexpected kill and await crash & recovery
  const crashPromise = new Promise(resolve => restartServer.once('crash', resolve));
  proc.kill('SIGKILL');
  await crashPromise;

  // Await recovery
  await restartServer.waitForReady(5000);
  assert.strictEqual(restartServer.status, 'CONNECTED', 'Server should recover to CONNECTED');
  assert(restartServer.retryCount >= 1, 'retryCount should have incremented');

  // Verify it can still execute tools after recovery
  const postRecoverRes = await restartServer.callTool('external_fetch_data', { query: 'after_restart' });
  assert(postRecoverRes.content[0].text.includes('after_restart'));
  restartServer.stop();

  // 11. Max Restarts Exhaustion
  const exhaustServer = new ExternalProcessServer({
    name: 'ext_exhaust_test',
    command: 'node',
    args: [mockServerPath],
    autoRestart: true,
    maxRetries: 1,
    restartDelayMs: 20
  });
  await exhaustServer.start();

  let exhaustedEmitted = false;
  exhaustServer.on('restartExhausted', () => {
    exhaustedEmitted = true;
  });

  // Crash once and wait for recovery (retryCount becomes 1)
  const crash1 = new Promise(resolve => exhaustServer.once('crash', resolve));
  exhaustServer.process.kill('SIGKILL');
  await crash1;
  await exhaustServer.waitForReady(5000);
  assert.strictEqual(exhaustServer.status, 'CONNECTED');

  // Crash second time (exhausts maxRetarts=1)
  const exhaustedPromise = new Promise(resolve => exhaustServer.once('restartExhausted', resolve));
  exhaustServer.process.kill('SIGKILL');
  await exhaustedPromise;

  assert.strictEqual(exhaustServer.status, 'FAILED', 'Status should transition to FAILED upon retry exhaustion');
  assert.strictEqual(exhaustedEmitted, true, 'restartExhausted event must be emitted');
  exhaustServer.stop();

  // 12. Graceful Shutdown with SIGKILL Fallback
  const fs = require('node:fs');
  const stubServerPath = path.join(__dirname, 'stubborn-server.tmp.js');
  const stubbornScript = `
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    const timer = setInterval(() => {}, 10000);
    process.on('SIGTERM', () => {
      // Stubbornly ignore SIGTERM
    });
    rl.on('line', (line) => {
      try {
        const msg = JSON.parse(line.trim());
        if (msg.method === 'initialize') {
          process.stdout.write(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'stubborn', version: '1.0' } }
          }) + '\\n');
        } else if (msg.method === 'tools/list') {
          process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { tools: [] } }) + '\\n');
        }
      } catch {}
    });
  `;
  fs.writeFileSync(stubServerPath, stubbornScript);

  try {
    const stubbornServer = new ExternalProcessServer({
      name: 'ext_stubborn',
      command: 'node',
      args: [stubServerPath],
      autoRestart: false
    });
    await stubbornServer.start();
    assert.strictEqual(stubbornServer.status, 'CONNECTED');
    const stubbornProc = stubbornServer.process;

    const exitPromise = new Promise(resolve => stubbornProc.once('exit', resolve));
    stubbornServer.stop(100);
    await exitPromise;

    assert.strictEqual(stubbornProc.killed || stubbornProc.exitCode !== null, true, 'Stubborn process must be killed by SIGKILL escalation');
  } finally {
    try { fs.unlinkSync(stubServerPath); } catch {}
  }

  console.log('✅ External MCP Server stdio Proxy Tunneling: All 12 test cases passed!');
}

module.exports = { runExternalServerTests };

if (require.main === module) {
  runExternalServerTests().catch(err => {
    console.error('External Server Test Failed:', err);
    process.exit(1);
  });
}
