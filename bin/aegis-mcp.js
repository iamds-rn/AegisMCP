#!/usr/bin/env node

/**
 * AegisMCP Command-Line Interface
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const pkg = require('../package.json');
const { AegisProxyServer } = require('../src/protocol/proxy');
const { VirtualHub } = require('../src/servers/virtualHub');
const { ProtocolFuzzer } = require('../src/fuzzer/fuzzer');
const { FirewallEngine } = require('../src/firewall/engine');
const { AuditLedger } = require('../src/ledger/auditLedger');
const { DynamicRuleSynthesizer } = require('../src/firewall/synthesizer');
const { ExploitPayloadGenerator } = require('../src/firewall/exploitGenerator');
const { ClientConfigGenerator } = require('../src/protocol/configGenerator');
const { DAGEngine } = require('../src/pipeline/dagEngine');

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
  --pipeline <file>           Execute a DAG pipeline definition with concurrent tier execution
  --generate-config <client>  Generate drop-in client config (claude | cursor | zed | windsurf | all)
  --synthesize <tool>         Synthesize tailored zero-trust security rules for an MCP tool
  --exploit-test <tool>       Run automated adversarial exploit audit and auto-synthesize countermeasures
  --fuzz                      Run automated adversarial fuzzing audit on target tool
  --verify-ledger             Perform cryptographic integrity check on audit ledger
  --forensics                 Run deep cryptographic tamper localization & blast radius forensics
  --help, -h                  Show this help manual

OPTIONS:
  --port <num>                Port for HTTP server (default: 3333)
  --mode <mode>               Firewall mode: ENFORCE, AUDIT_ONLY, SANITIZE (default: ENFORCE)
  --tool <name>               Target tool name (for fuzzing or rule synthesis, default: read_file)
  --upstream <cmd>            External upstream command to wrap
  --supervise                 Enable automatic crash-backoff supervision for proxied process
  --retries <num>             Max restart retries for supervised external server (default: 3)

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

  const upstreamIdx = args.indexOf('--upstream');
  const proxyIdx = args.indexOf('--proxy');
  const upstreamCommand = (proxyIdx !== -1 && args[proxyIdx + 1] && !args[proxyIdx + 1].startsWith('--'))
    ? args[proxyIdx + 1]
    : (upstreamIdx !== -1 && args[upstreamIdx + 1] && !args[upstreamIdx + 1].startsWith('--'))
      ? args[upstreamIdx + 1]
      : null;

  // 1. Client Config Generator: --generate-config <client>
  const configIdx = args.indexOf('--generate-config');
  if (configIdx !== -1) {
    const client = (args[configIdx + 1] && !args[configIdx + 1].startsWith('--')) ? args[configIdx + 1] : 'all';
    try {
      const config = ClientConfigGenerator.generate(client, {
        mode,
        port,
        proxyCommand: upstreamCommand
      });
      console.log(`\n📋 AegisMCP Client Configuration for [${client.toUpperCase()}]:\n`);
      console.log(JSON.stringify(config, null, 2));
      console.log('\n💡 Setup Instruction:', config.instruction || 'Paste into client settings.');
    } catch (err) {
      console.error(`❌ Error generating config: ${err.message}`);
      process.exit(1);
    }
    return;
  }

  // 2. Automated Adversarial Exploit Test: --exploit-test <tool>
  const exploitIdx = args.indexOf('--exploit-test');
  if (exploitIdx !== -1) {
    const targetTool = (args[exploitIdx + 1] && !args[exploitIdx + 1].startsWith('--')) ? args[exploitIdx + 1] : 'read_file';
    console.log(`\n⚔️  Running Automated Adversarial Exploit Audit against "${targetTool}"...\n`);

    const hub = new VirtualHub();
    const allTools = hub.listAllTools();
    const tool = allTools.find(t => t.name === targetTool);

    if (!tool) {
      console.error(`❌ Tool "${targetTool}" not found in Virtual Hub. Available:`);
      allTools.forEach(t => console.error(`  - ${t.name}`));
      process.exit(1);
    }

    const firewall = new FirewallEngine({ mode });
    const generator = new ExploitPayloadGenerator();
    const server = hub.getServer(tool.serverName);
    const invoker = (name, p) => server.callTool(name, p);

    const audit = await generator.runExploitAudit(tool, firewall, invoker);

    console.log(`🛡️  EXPLOIT IMMUNITY SCORECARD: [Grade: ${audit.grade}] (${audit.defenseScorePct}% Defended)`);
    console.log(`    Total Weaponized Exploits: ${audit.totalExploits}`);
    console.log(`    Defended / Intercepted:    ${audit.defendedCount}`);
    console.log(`    Vulnerable / Unmitigated:  ${audit.vulnerableCount}\n`);

    console.log('--- Adversarial Threat Breakdown ---');
    for (const r of audit.results) {
      const icon = r.status === 'DEFENDED' ? '🛡️ [DEFENDED]' : '⚠️ [VULNERABLE]';
      console.log(`${icon} [${r.category}] ${r.name}`);
      console.log(`    Status:     ${r.status}`);
      console.log(`    Mechanism:  ${r.defenseMechanism}`);
      if (r.autoRemediation) {
        console.log(`    Auto-Remedy: Synthesized rule [${r.autoRemediation.ruleId}] ${r.autoRemediation.ruleName}`);
      }
      console.log('');
    }
    return;
  }

  // 3. External Server Stdio Proxy Tunnel: --proxy <command>
  if (proxyIdx !== -1) {
    if (!upstreamCommand) {
      console.error('❌ Error: --proxy requires an upstream command string (e.g. --proxy "npx -y @modelcontextprotocol/server-filesystem /tmp")');
      process.exit(1);
    }
    const supervise = args.includes('--supervise') || args.includes('--auto-restart');
    const retriesIdx = args.indexOf('--retries');
    const maxRetries = retriesIdx !== -1 ? parseInt(args[retriesIdx + 1], 10) : (supervise ? 3 : 0);
    const server = new AegisProxyServer({
      upstreamCommand,
      upstreamOptions: {
        autoRestart: supervise || maxRetries > 0,
        maxRetries: maxRetries > 0 ? maxRetries : 3
      }
    });
    server.firewall.setMode(mode);
    await server.startStdio();
    return;
  }

  // 4. Standard Stdio Gateway
  if (args.includes('--stdio')) {
    const server = new AegisProxyServer();
    server.firewall.setMode(mode);
    await server.startStdio();
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

  // 9. DAG Pipeline Execution: --pipeline <file>
  const pipelineIdx = args.indexOf('--pipeline');
  if (pipelineIdx !== -1) {
    const pipelinePath = args[pipelineIdx + 1];
    if (!pipelinePath || pipelinePath.startsWith('--')) {
      console.error('❌ Error: --pipeline requires a path to a JSON pipeline file');
      process.exit(1);
    }
    const hub = new VirtualHub();
    try {
      const fullPath = path.resolve(pipelinePath);
      const pipelineDef = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      console.log(`\n⛓️  Executing DAG Pipeline: "${pipelineDef.name || pipelineDef.id}" (${pipelineDef.nodes ? pipelineDef.nodes.length : 0} nodes)...\n`);

      const ledger = new AuditLedger();
      const firewall = new FirewallEngine({ mode });
      const dagEngine = new DAGEngine({ firewall, ledger });

      // Support external servers declared in pipeline definition
      if (Array.isArray(pipelineDef.servers)) {
        for (const srv of pipelineDef.servers) {
          if (srv.name && (srv.command || srv.url)) {
            await hub.registerExternalServer({
              name: srv.name,
              command: srv.command,
              args: srv.args,
              url: srv.url,
              ledger,
              autoRestart: true
            });
          }
        }
      }

      const tiers = dagEngine.partitionIntoTiers(pipelineDef.nodes);
      console.log(`📊 Topological Partitioning: ${tiers.length} concurrent execution tiers`);
      tiers.forEach((t, i) => console.log(`   Tier ${i}: [${t.map(n => n.id).join(', ')}] (${t.length} parallel nodes)`));

      const invoker = (server, tool, params) => hub.executeTool(server, tool, params);
      const result = await dagEngine.executePipeline(pipelineDef, invoker);

      console.log(`\n✅ Pipeline "${result.pipelineId}" COMPLETED in ${result.totalDurationMs}ms`);
      console.log(`   Steps Executed: ${result.stepsExecuted}`);
      console.log(`   Tiers Executed: ${result.tiersExecuted}`);
      for (const t of result.tierExecutions) {
        console.log(`   - Tier #${t.tierIndex} (${t.nodeCount} nodes): ${t.durationMs}ms | SHA-256 Hash: ${t.tierHash}`);
      }
      return;
    } catch (err) {
      console.error(`❌ Pipeline execution failed: ${err.message}`);
      process.exit(1);
    } finally {
      hub.shutdownAll();
    }
  }

  printHelp();
}

main().catch(err => {
  console.error('Fatal CLI Error:', err);
  process.exit(1);
});
