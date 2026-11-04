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

const args = process.argv.slice(2);

function printHelp() {
  console.log(`
🛡️  AegisMCP - Zero-Trust Security Firewall & Resilience Studio for MCP
Version: ${pkg.version}

USAGE:
  aegis-mcp [command] [options]

COMMANDS:
  --serve              Launch Web Studio & API Gateway (Default port: 3333)
  --stdio              Run MCP stdio proxy with active firewall protection
  --fuzz               Run automated protocol fuzzing audit on virtual tools
  --verify-ledger      Perform cryptographic integrity check on audit ledger
  --help, -h           Show this help manual

OPTIONS:
  --port <num>         Port for HTTP server (default: 3333)
  --mode <mode>        Firewall mode: ENFORCE, AUDIT_ONLY, SANITIZE (default: ENFORCE)
  --tool <name>        Target tool name for fuzzing (default: read_file)

EXAMPLES:
  $ aegis-mcp --serve --port 8080
  $ aegis-mcp --stdio
  $ aegis-mcp --fuzz --tool write_file
  $ aegis-mcp --verify-ledger
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

  if (args.includes('--stdio')) {
    const server = new AegisProxyServer();
    server.firewall.setMode(mode);
    server.startStdio();
    return;
  }

  if (args.includes('--serve')) {
    const server = new AegisProxyServer({ port });
    server.firewall.setMode(mode);
    await server.startHttp(port);
    console.log(`
🛡️  ==============================================================
    AEGIS-MCP STUDIO & GATEWAY ACTIVE
    --------------------------------------------------------------
    Web Cockpit:    http://localhost:${port}
    JSON-RPC RPC:   http://localhost:${port}/rpc
    Health API:     http://localhost:${port}/health
    Ledger Audit:   http://localhost:${port}/api/ledger/verify
    Firewall Mode:  ${mode}
    Virtual Hub:    4 In-Memory Servers Loaded
    Integrity:      Merkle Hash Chain Active
============================================================== 🛡️
`);
    return;
  }

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
