#!/usr/bin/env node

/**
 * AegisMCP Command-Line Interface
 */

'use strict';

const pkg = require('../package.json');
const { AegisProxyServer } = require('../src/protocol/proxy');
const { VirtualHub } = require('../src/servers/virtualHub');
const { ProtocolFuzzer } = require('../src/fuzzer/fuzzer');
const { FirewallEngine } = require('../src/firewall/engine');
const { AuditLedger } = require('../src/ledger/auditLedger');
const { DynamicRuleSynthesizer } = require('../src/firewall/synthesizer');
const { ClientConfigGenerator } = require('../src/protocol/configGenerator');

const args = process.argv.slice(2);

function printHelp() {
  console.log(`
🛡️  AegisMCP - Zero-Trust Security Firewall, Resilience Fuzzer & Visual Observability Studio
Version: ${pkg.version}

USAGE:
  aegis-mcp [command] [options]

COMMANDS:
  --serve                     Launch Web Studio & API Gateway (Default port: 3333)
  --stdio                     Run MCP stdio proxy with active zero-trust firewall protection
  --proxy <command>           Wrap & shield an external MCP server stdio command with Aegis firewall
  --generate-config <client>  Generate drop-in client config (claude | cursor | zed | windsurf | all)
  --synthesize <tool>         Synthesize tailored zero-trust security rules for an MCP tool
  --fuzz                      Run automated adversarial fuzzing audit on target tool
  --verify-ledger             Perform cryptographic integrity check on audit ledger
  --forensics                 Run deep cryptographic tamper localization & blast radius forensics
  --help, -h                  Show this help manual

OPTIONS:
  --port <num>                Port for HTTP server (default: 3333)
  --mode <mode>               Firewall mode: ENFORCE, AUDIT_ONLY, SANITIZE (default: ENFORCE)
  --tool <name>               Target tool name (for fuzzing or rule synthesis, default: read_file)
  --upstream <cmd>            External upstream command to wrap

EXAMPLES:
  # Launch the Web Studio Cockpit
  $ aegis-mcp --serve --port 3333

  # Zero-Trust Stdio Proxy for Claude Desktop / Cursor
  $ aegis-mcp --stdio --mode ENFORCE

  # Shield an external real MCP server with Aegis Zero-Trust Firewall
  $ aegis-mcp --proxy "npx -y @modelcontextprotocol/server-filesystem /tmp" --mode ENFORCE

  # Generate 1-click Claude Desktop configuration
  $ aegis-mcp --generate-config claude

  # Generate 1-click Cursor configuration
  $ aegis-mcp --generate-config cursor

  # Synthesize tailored firewall defense rules for a tool schema
  $ aegis-mcp --synthesize read_file

  # Perform deep forensic analysis and tamper localization
  $ aegis-mcp --forensics
`);
}

async function main() {
  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    printHelp();
    return;
  }

  const portIdx = args.indexOf('--port');
  const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : 3333;

  const modeIdx = args.indexOf('--mode');
  const mode = modeIdx !== -1 ? args[modeIdx + 1].toUpperCase() : 'ENFORCE';

  // 1. External Server Stdio Proxy Tunnel: --proxy <command>
  const proxyIdx = args.indexOf('--proxy');
  if (proxyIdx !== -1) {
    const upstreamCommand = args[proxyIdx + 1];
    if (!upstreamCommand) {
      console.error('❌ Error: --proxy requires an upstream command string (e.g. --proxy "npx -y @modelcontextprotocol/server-filesystem /tmp")');
      process.exit(1);
    }
    const server = new AegisProxyServer({ upstreamCommand });
    server.firewall.setMode(mode);
    await server.startStdio();
    return;
  }

  // 2. Standard Stdio Gateway
  if (args.includes('--stdio')) {
    const server = new AegisProxyServer();
    server.firewall.setMode(mode);
    await server.startStdio();
    return;
  }

  // 3. Client Config Generator: --generate-config <client>
  const configIdx = args.indexOf('--generate-config');
  if (configIdx !== -1) {
    const client = args[configIdx + 1] || 'all';
    try {
      const config = ClientConfigGenerator.generate(client, { mode, port });
      console.log(`\n📋 AegisMCP Client Configuration for [${client.toUpperCase()}]:\n`);
      console.log(JSON.stringify(config, null, 2));
      console.log('\n💡 Setup Instruction:', config.instruction || 'Paste into client settings.');
    } catch (err) {
      console.error(`❌ Error generating config: ${err.message}`);
      process.exit(1);
    }
    return;
  }

  // 4. Dynamic Rule Synthesizer: --synthesize <tool>
  const synthIdx = args.indexOf('--synthesize');
  if (synthIdx !== -1) {
    const targetTool = args[synthIdx + 1] || 'read_file';
    console.log(`\n🧬 Synthesizing Zero-Trust Security Rules for tool "${targetTool}"...\n`);

    const hub = new VirtualHub();
    const allTools = hub.listAllTools();
    const tool = allTools.find(t => t.name === targetTool);

    if (!tool) {
      console.error(`❌ Tool "${targetTool}" not found. Available tools:`);
      allTools.forEach(t => console.error(`  - ${t.name}`));
      process.exit(1);
    }

    const synthesizer = new DynamicRuleSynthesizer();
    const rules = synthesizer.synthesizeRulesForTool(tool);

    console.log(`✨ Synthesized ${rules.length} custom security defense rules for "${targetTool}":\n`);
    for (const r of rules) {
      console.log(`🛡️  [${r.id}] ${r.name}`);
      console.log(`    Category:    ${r.category}`);
      console.log(`    Severity:    ${r.severity}`);
      console.log(`    Description: ${r.description}`);
      console.log(`    Pattern:     ${r.patternDescription}\n`);
    }
    return;
  }

  // 5. Deep Cryptographic Forensics: --forensics
  if (args.includes('--forensics')) {
    console.log('\n🔍 Running Aegis Deep Cryptographic Ledger Forensics...\n');
    const ledger = new AuditLedger();
    ledger.append('TOOL_CALL', { tool: 'read_file', path: '/workspace/project.json' });
    ledger.append('FIREWALL_BLOCK', { tool: 'write_file', ruleId: 'SEC-001', threat: 'Path Traversal' });
    ledger.append('TOOL_CALL', { tool: 'list_files', path: '/workspace' });

    console.log('--- Phase 1: Verifying Pristine Ledger ---');
    const pristineForensics = ledger.locateTamper();
    console.log(`Status: ${pristineForensics.intact ? '✅ PRISTINE' : '❌ COMPROMISED'}`);
    console.log(`Summary: ${pristineForensics.forensicSummary}\n`);

    console.log('--- Phase 2: Adversary Tamper Simulation (Corrupting block #1) ---');
    ledger.tamper(1, { tool: 'read_file', path: '/workspace/falsified_data.txt', covertAuditErase: true });
    const tamperedForensics = ledger.locateTamper();
    console.log(`Status: ${tamperedForensics.intact ? '✅ PRISTINE' : '❌ COMPROMISED'}`);
    console.log(`Summary: ${tamperedForensics.forensicSummary}`);
    console.log(`Tampered Block Index: #${tamperedForensics.tamperedIndex}`);
    console.log(`Invalidation Blast Radius: ${tamperedForensics.cascadeBlastRadius} blocks downstream`);
    if (tamperedForensics.fieldDiff) {
      console.log('Payload Field Diff:');
      console.log(JSON.stringify(tamperedForensics.fieldDiff, null, 2));
    }

    console.log('\n--- Phase 3: Cryptographic Healing & Chain Restoration ---');
    const restoreResult = ledger.restoreAll();
    console.log(`Restored ${restoreResult.restoredCount} blocks.`);
    console.log(`Re-verification: ${restoreResult.verification.valid ? '✅ CHAIN RESTORED INTACT' : '❌ FAILED'}\n`);
    return;
  }

  // 6. Web Studio & Gateway: --serve
  if (args.includes('--serve')) {
    const server = new AegisProxyServer({ port });
    server.firewall.setMode(mode);
    await server.startHttp(port);
    console.log(`
🛡️  ==============================================================
    AEGIS-MCP STUDIO & GATEWAY ACTIVE (v${pkg.version})
    --------------------------------------------------------------
    Web Cockpit:      http://localhost:${port}
    JSON-RPC RPC:     http://localhost:${port}/rpc
    Health API:       http://localhost:${port}/health
    Servers Manager:  http://localhost:${port}/api/servers
    Firewall Rules:   http://localhost:${port}/api/firewall/rules
    Ledger Forensics: http://localhost:${port}/api/ledger/forensics
    Client Configs:   http://localhost:${port}/api/configs/claude
    Firewall Mode:    ${mode}
    Virtual Hub:      In-Memory Virtual Server Fleet Active
    Merkle Ledger:    Continuous Hash Chain Active
============================================================== 🛡️
`);
    return;
  }

  // 7. Protocol Fuzzer: --fuzz
  if (args.includes('--fuzz')) {
    const toolIdx = args.indexOf('--tool');
    const targetTool = toolIdx !== -1 ? args[toolIdx + 1] : 'read_file';

    console.log(`\n🔍 Launching Aegis Protocol Fuzzer against "${targetTool}"...\n`);
    const hub = new VirtualHub();
    const firewall = new FirewallEngine({ mode });
    const fuzzer = new ProtocolFuzzer();

    const allTools = hub.listAllTools();
    const tool = allTools.find(t => t.name === targetTool);

    if (!tool) {
      console.error(`❌ Error: Tool "${targetTool}" not found. Available tools:`);
      allTools.forEach(t => console.error(`  - ${t.name} (${t.serverName})`));
      process.exit(1);
    }

    const server = hub.getServer(tool.serverName);
    const invoker = (name, p) => server.callTool(name, p);

    const audit = await fuzzer.runAudit(tool, invoker, firewall);
    console.log(fuzzer.generateMarkdownReport(audit));
    return;
  }

  // 8. Cryptographic Ledger Check: --verify-ledger
  if (args.includes('--verify-ledger')) {
    console.log('\n🔐 Running cryptographic ledger integrity check...\n');
    const ledger = new AuditLedger();
    ledger.append('SAMPLE_TOOL_CALL', { tool: 'read_file', user: 'agent-1' });
    ledger.append('SAMPLE_FIREWALL_BLOCK', { rule: 'SEC-001', threat: 'Directory Traversal' });

    const verification = ledger.verify();
    console.log('Result:', JSON.stringify(verification, null, 2));

    if (verification.valid) {
      console.log(`\n✅ Ledger verified intact across ${verification.blockCount} blocks.`);
    } else {
      console.log(`\n❌ Integrity broken at block #${verification.brokenIndex}!`);
      process.exit(1);
    }
    return;
  }

  printHelp();
}

main().catch(err => {
  console.error('Fatal CLI Error:', err);
  process.exit(1);
});
