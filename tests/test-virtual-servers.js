/**
 * Tests for AegisMCP Virtual In-Memory MCP Servers
 */

'use strict';

const assert = require('node:assert');
const { VirtualHub } = require('../src/servers/virtualHub');

async function runVirtualServerTests() {
  console.log('🧪 Testing Virtual MCP Servers...');

  const hub = new VirtualHub();
  const servers = hub.listServers();
  assert.strictEqual(servers.length, 4, 'Must have 4 registered virtual servers');

  // 1. Filesystem Server
  const fs = hub.getServer('virtual_filesystem');
  const initialList = await fs.callTool('list_files', { path: '/workspace' });
  assert(initialList.content[0].text.includes('/workspace/project.json'));

  // write file
  await fs.callTool('write_file', { path: '/workspace/test.txt', content: 'Aegis Sentinel Active' });
  const readBack = await fs.callTool('read_file', { path: '/workspace/test.txt' });
  assert.strictEqual(readBack.content[0].text, 'Aegis Sentinel Active');

  // stat file
  const stat = JSON.parse((await fs.callTool('file_stat', { path: '/workspace/test.txt' })).content[0].text);
  assert.strictEqual(stat.sizeBytes, 21);

  // delete file
  await fs.callTool('delete_file', { path: '/workspace/test.txt' });
  await assert.rejects(() => fs.callTool('read_file', { path: '/workspace/test.txt' }), /File not found/);

  // 2. Memory KV Server
  const mem = hub.getServer('virtual_memory');
  await mem.callTool('set_key', { key: 'user:session:42', value: { role: 'admin' }, tags: ['auth', 'session'] });
  const getRes = JSON.parse((await mem.callTool('get_key', { key: 'user:session:42' })).content[0].text);
  assert.strictEqual(getRes.value.role, 'admin');

  const searchRes = JSON.parse((await mem.callTool('search_keys', { query: 'session' })).content[0].text);
  assert(searchRes.count >= 1);

  // 3. Crypto Server
  const cryptoServer = hub.getServer('virtual_crypto');
  const hashRes = JSON.parse((await cryptoServer.callTool('hash_sha256', { text: 'hello world' })).content[0].text);
  assert.strictEqual(hashRes.hash, 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');

  const hmacRes = JSON.parse((await cryptoServer.callTool('hmac_sign', { secret: 'secret_key', message: 'payload' })).content[0].text);
  assert.strictEqual(hmacRes.signature.length, 64);

  const tokenRes = JSON.parse((await cryptoServer.callTool('generate_token', { bytes: 32, format: 'hex' })).content[0].text);
  assert.strictEqual(tokenRes.token.length, 64);
  assert(tokenRes.shannonEntropy > 3.0);

  const entropyRes = JSON.parse((await cryptoServer.callTool('eval_entropy', { text: tokenRes.token })).content[0].text);
  assert(entropyRes.shannonEntropy > 3.0);

  // 4. HTTP Simulator Server
  const httpSim = hub.getServer('virtual_http_simulator');
  const ghStatus = JSON.parse((await httpSim.callTool('fetch_url', { url: 'https://api.github.com/status' })).content[0].text);
  assert(ghStatus.status.includes('operational'));

  // 5. Strict Parameter Validation Invariant Tests
  console.log('  Testing server parameter validation invariants...');
  await assert.rejects(() => fs.callTool('read_file', {}), /Parameter "path" is required/);
  await assert.rejects(() => fs.callTool('write_file', {}), /Parameter "path" is required/);
  await assert.rejects(() => fs.callTool('write_file', { path: '/workspace/test.txt' }), /Parameter "content" is required/);
  await assert.rejects(() => fs.callTool('delete_file', {}), /Parameter "path" is required/);
  await assert.rejects(() => fs.callTool('file_stat', {}), /Parameter "path" is required/);
  await assert.rejects(() => fs.callTool('list_files', {}), /Parameter "path" is required/);

  await assert.rejects(() => mem.callTool('set_key', {}), /Parameter "key" is required/);
  await assert.rejects(() => mem.callTool('set_key', { key: 'sample' }), /Parameter "value" is required/);
  await assert.rejects(() => mem.callTool('get_key', {}), /Parameter "key" is required/);
  await assert.rejects(() => mem.callTool('delete_key', {}), /Parameter "key" is required/);
  await assert.rejects(() => mem.callTool('search_keys', {}), /Parameter "query" is required/);

  await assert.rejects(() => cryptoServer.callTool('hash_sha256', {}), /Parameter "text" is required/);
  await assert.rejects(() => cryptoServer.callTool('hmac_sign', {}), /Parameter "secret" is required/);
  await assert.rejects(() => cryptoServer.callTool('hmac_sign', { secret: 'sec' }), /Parameter "message" is required/);
  await assert.rejects(() => cryptoServer.callTool('eval_entropy', {}), /Parameter "text" is required/);

  await assert.rejects(() => httpSim.callTool('fetch_url', {}), /Parameter "url" is required/);

  console.log('✅ Virtual In-Memory MCP Servers: All 4 servers passed verification!');
}

module.exports = { runVirtualServerTests };

if (require.main === module) {
  runVirtualServerTests().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
