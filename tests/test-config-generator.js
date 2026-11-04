/**
 * Tests for AegisMCP Client Configuration Generator
 */

'use strict';

const assert = require('node:assert');
const { ClientConfigGenerator } = require('../src/protocol/configGenerator');

function runConfigGeneratorTests() {
  console.log('🧪 Testing AI Client Configuration Generator...');

  // 1. Claude Desktop config
  const claudeCfg = ClientConfigGenerator.generate('claude', { mode: 'ENFORCE', port: 3333 });
  assert.strictEqual(claudeCfg.name, 'Claude Desktop');
  assert(claudeCfg.snippet.mcpServers['aegis-security-gateway'], 'Snippet must contain aegis-security-gateway key');
  assert.strictEqual(claudeCfg.snippet.mcpServers['aegis-security-gateway'].command, 'node');
  assert(claudeCfg.snippet.mcpServers['aegis-security-gateway'].args.includes('--stdio'));
  assert(claudeCfg.snippet.mcpServers['aegis-security-gateway'].args.includes('ENFORCE'));

  // 2. Cursor config
  const cursorCfg = ClientConfigGenerator.generate('cursor', { mode: 'AUDIT_ONLY' });
  assert.strictEqual(cursorCfg.name, 'Cursor IDE');
  assert(cursorCfg.configPath.includes('.cursor'));
  assert(cursorCfg.snippet.mcpServers['aegis-security-gateway'].args.includes('AUDIT_ONLY'));

  // 3. Zed config
  const zedCfg = ClientConfigGenerator.generate('zed');
  assert.strictEqual(zedCfg.name, 'Zed Editor');
  assert(zedCfg.snippet.context_servers['aegis-security-gateway'].command.path === 'node');

  // 4. Windsurf config
  const windsurfCfg = ClientConfigGenerator.generate('windsurf');
  assert.strictEqual(windsurfCfg.name, 'Windsurf / Codeium');
  assert(windsurfCfg.configPath.includes('windsurf'));

  // 5. Proxy Tunnel Config wrapping upstream command
  const proxyWrapCfg = ClientConfigGenerator.generate('claude', {
    mode: 'ENFORCE',
    proxyCommand: 'npx -y @modelcontextprotocol/server-filesystem /tmp'
  });
  assert(proxyWrapCfg.snippet.mcpServers['aegis-shielded-upstream'], 'Should use shielded-upstream server key');
  assert(proxyWrapCfg.snippet.mcpServers['aegis-shielded-upstream'].args.includes('--proxy'));
  assert(proxyWrapCfg.snippet.mcpServers['aegis-shielded-upstream'].args.includes('npx -y @modelcontextprotocol/server-filesystem /tmp'));

  // 6. Generate All Configs
  const allConfigs = ClientConfigGenerator.generate('all');
  assert(allConfigs.claude && allConfigs.cursor && allConfigs.zed && allConfigs.windsurf && allConfigs.http);

  // 7. Invalid client error check
  assert.throws(() => ClientConfigGenerator.generate('unknown_editor'), /Unsupported client/);

  console.log('✅ Client Configuration Generator: All 7 test cases passed!');
}

module.exports = { runConfigGeneratorTests };

if (require.main === module) {
  runConfigGeneratorTests();
}
