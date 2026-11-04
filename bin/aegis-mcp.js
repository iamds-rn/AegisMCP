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

const rawArgs = process.argv.slice(2);

function printHelp() {
  console.log(`
🛡️  AegisMCP - Zero-Trust Security Firewall, Resilience Fuzzer & Visual Observability Studio
Version: v${pkg.version}

USAGE:
  aegis-mcp [command] [options]

COMMANDS:
  serve, --serve              Launch Web Studio & API Gateway (Default port: 3333)
  stdio, --stdio              Run MCP stdio proxy with active zero-trust firewall protection
  proxy <command>, --proxy    Wrap & shield an external MCP server stdio command with Aegis firewall
  pipeline <file>, --pipeline Execute a DAG pipeline definition with concurrent tier execution
  config <client>, --config   Generate drop-in client config (claude | cursor | zed | windsurf | all)
  synthesize <tool>, --synthesize Synthesize tailored zero-trust security rules for an MCP tool
  exploit-test <tool>, --exploit-test Run automated adversarial exploit audit and auto-synthesize countermeasures
  fuzz, --fuzz                Run automated adversarial fuzzing audit on target tool
  verify, --verify            Perform cryptographic integrity check on audit ledger
  forensics, --forensics      Run deep cryptographic tamper localization & blast radius forensics
  verify-proof <file>, --verify-proof <file> Verify a cryptographic Merkle inclusion proof
  immune-audit, --immune-audit Run autonomous adaptive immune mutation audit
  metrics, --metrics          Export standard Prometheus operational metrics
  --version, -v               Print version and exit 0
  --help, -h                  Show this help manual

OPTIONS:
  --port, -p <num>            Port for HTTP server (1-65535, default: 3333)
  --host, -H <host>           Host to bind HTTP server (default: 127.0.0.1)
  --mode, -m <mode>           Firewall mode: ENFORCE, AUDIT_ONLY, SANITIZE (default: ENFORCE)
  --tool, -t <name>           Target tool name (for fuzzing or rule synthesis, default: read_file)
  --upstream <cmd>            External upstream command to wrap
  --supervise                 Enable automatic crash-backoff supervision for proxied process
  --retries <num>             Max restart retries for supervised external server (default: 3)
  --verbose                   Enable verbose logging

EXAMPLES:
  # Launch the Web Studio Cockpit
  $ aegis-mcp serve --port 3333

  # Zero-Trust Stdio Proxy for Claude Desktop / Cursor
  $ aegis-mcp stdio --mode ENFORCE

  # Shield an external real MCP server with Aegis Zero-Trust Firewall
  $ aegis-mcp proxy "npx -y @modelcontextprotocol/server-filesystem /tmp" --mode ENFORCE

  # Generate 1-click Claude Desktop configuration
  $ aegis-mcp config claude

  # Generate 1-click Cursor configuration
  $ aegis-mcp config cursor

  # Synthesize tailored firewall defense rules for a tool schema
  $ aegis-mcp synthesize read_file

  # Perform deep forensic analysis and tamper localization
  $ aegis-mcp forensics
`);
}

async function main() {
  if (rawArgs.length === 0 || rawArgs.includes('--help') || rawArgs.includes('-h') || rawArgs[0] === 'help') {
    printHelp();
    process.exit(0);
  }

  if (rawArgs.includes('--version') || rawArgs.includes('-v') || rawArgs[0] === 'version') {
    console.log(`v${pkg.version}`);
    process.exit(0);
  }

  const recognizedCommands = [
    'serve', 'stdio', 'proxy', 'config', 'synthesize', 'exploit-test',
    'fuzz', 'verify', 'forensics', 'pipeline', 'verify-proof', 'immune-audit', 'metrics', 'help', 'version'
  ];

  const recognizedFlags = new Set([
    '--help', '-h',
    '--version', '-v',
    '--serve',
    '--stdio',
    '--proxy',
    '--config', '--generate-config',
    '--synthesize',
    '--exploit-test',
    '--fuzz',
    '--verify', '--verify-ledger',
    '--forensics',
    '--pipeline',
    '--verify-proof',
    '--immune-audit',
    '--metrics',
    '--port', '-p',
    '--host', '-H',
    '--mode', '-m',
    '--tool', '-t',
    '--upstream',
    '--supervise', '--auto-restart',
    '--retries',
    '--verbose'
  ]);

  // Validate all flags
  for (let i = 0; i < rawArgs.length; i++) {
    const arg = rawArgs[i];
    if (arg.startsWith('-')) {
      if (!recognizedFlags.has(arg)) {
        console.error(`❌ Error: Unrecognized flag "${arg}". Run aegis-mcp --help for usage.`);
        process.exit(1);
      }
    }
  }

  // Determine command and positional arguments
  let command = null;
  let commandArg = null;
  const positionalArgs = [];

  for (let i = 0; i < rawArgs.length; i++) {
    const arg = rawArgs[i];
    if (arg.startsWith('-')) {
      // If this flag takes an argument, skip next token if present
      if (['--port', '-p', '--host', '-H', '--mode', '-m', '--tool', '-t', '--upstream', '--retries'].includes(arg)) {
        i++;
      } else if (['--proxy', '--config', '--generate-config', '--synthesize', '--exploit-test', '--pipeline', '--verify-proof'].includes(arg)) {
        if (i + 1 < rawArgs.length && !rawArgs[i + 1].startsWith('-')) {
          i++;
        }
      }
    } else {
      positionalArgs.push({ index: i, val: arg });
    }
  }

  if (positionalArgs.length > 0) {
    const first = positionalArgs[0].val;
    if (recognizedCommands.includes(first)) {
      command = first;
      if (positionalArgs.length > 1) {
        commandArg = positionalArgs[1].val;
      }
    } else {
      console.error(`❌ Error: Unknown command "${first}". Run aegis-mcp --help for usage.`);
      process.exit(1);
    }
  }

  // If command not determined from positional, check flags
  if (!command) {
    if (rawArgs.includes('--serve')) command = 'serve';
    else if (rawArgs.includes('--stdio')) command = 'stdio';
    else if (rawArgs.includes('--proxy')) command = 'proxy';
    else if (rawArgs.includes('--config') || rawArgs.includes('--generate-config')) command = 'config';
    else if (rawArgs.includes('--pipeline')) command = 'pipeline';
    else if (rawArgs.includes('--synthesize')) command = 'synthesize';
    else if (rawArgs.includes('--exploit-test')) command = 'exploit-test';
    else if (rawArgs.includes('--fuzz')) command = 'fuzz';
    else if (rawArgs.includes('--verify') || rawArgs.includes('--verify-ledger')) command = 'verify';
    else if (rawArgs.includes('--forensics')) command = 'forensics';
    else if (rawArgs.includes('--verify-proof')) command = 'verify-proof';
    else if (rawArgs.includes('--immune-audit')) command = 'immune-audit';
    else if (rawArgs.includes('--metrics')) command = 'metrics';
  }

  // Parse and validate --port / -p
  let port = 3333;
  const portIdx = rawArgs.findIndex(a => a === '--port' || a === '-p');
  if (portIdx !== -1) {
    const val = rawArgs[portIdx + 1];
    if (!val || val.startsWith('-') || !/^\d+$/.test(val)) {
      console.error('❌ Error: --port requires a valid port number between 1 and 65535');
      process.exit(1);
    }
    const p = parseInt(val, 10);
    if (p < 1 || p > 65535) {
      console.error('❌ Error: --port requires a valid port number between 1 and 65535');
      process.exit(1);
    }
    port = p;
  }

  // Parse and validate --mode / -m
  let mode = 'ENFORCE';
  const modeIdx = rawArgs.findIndex(a => a === '--mode' || a === '-m');
  if (modeIdx !== -1) {
    const val = rawArgs[modeIdx + 1];
    if (!val || val.startsWith('-')) {
      console.error('❌ Error: --mode requires a value (ENFORCE, AUDIT_ONLY, SANITIZE)');
      process.exit(1);
    }
    const m = val.toUpperCase();
    if (!['ENFORCE', 'AUDIT_ONLY', 'SANITIZE'].includes(m)) {
      console.error(`❌ Error: Invalid --mode "${val}". Must be ENFORCE, AUDIT_ONLY, or SANITIZE`);
      process.exit(1);
    }
    mode = m;
  }

  // Parse and validate --host / -H
  let host = '127.0.0.1';
  const hostIdx = rawArgs.findIndex(a => a === '--host' || a === '-H');
  if (hostIdx !== -1) {
    const val = rawArgs[hostIdx + 1];
    if (!val || val.startsWith('-')) {
      console.error('❌ Error: --host requires a valid hostname or IP address');
      process.exit(1);
    }
    host = val;
  }

  // Parse and validate --tool / -t
  let toolFromFlag = null;
  const toolIdx = rawArgs.findIndex(a => a === '--tool' || a === '-t');
  if (toolIdx !== -1) {
    const val = rawArgs[toolIdx + 1];
    if (!val || val.startsWith('-')) {
      console.error('❌ Error: --tool requires a tool name');
      process.exit(1);
    }
    toolFromFlag = val;
  }

  if (!command) {
    console.error('❌ Error: No command specified. Run aegis-mcp --help for usage.');
    process.exit(1);
  }

  // Parse upstream command
  const upstreamIdx = rawArgs.indexOf('--upstream');
  const proxyFlagIdx = rawArgs.indexOf('--proxy');
  let upstreamCommand = null;
  if (proxyFlagIdx !== -1 && rawArgs[proxyFlagIdx + 1] && !rawArgs[proxyFlagIdx + 1].startsWith('-')) {
    upstreamCommand = rawArgs[proxyFlagIdx + 1];
  } else if (upstreamIdx !== -1 && rawArgs[upstreamIdx + 1] && !rawArgs[upstreamIdx + 1].startsWith('-')) {
    upstreamCommand = rawArgs[upstreamIdx + 1];
  } else if (command === 'proxy' && commandArg) {
    upstreamCommand = commandArg;
  }

  // Supervise & retries
  const supervise = rawArgs.includes('--supervise') || rawArgs.includes('--auto-restart');
  const retriesIdx = rawArgs.indexOf('--retries');
  let maxRetries = supervise ? 3 : 0;
  if (retriesIdx !== -1) {
    const val = rawArgs[retriesIdx + 1];
    if (!val || val.startsWith('-') || isNaN(parseInt(val, 10))) {
      console.error('❌ Error: --retries requires a numeric value');
      process.exit(1);
    }
    maxRetries = parseInt(val, 10);
  }

  // 1. Client Config Generator: config | --config | --generate-config
  if (command === 'config') {
    let client = 'all';
    const cfgIdx = rawArgs.findIndex(a => a === '--config' || a === '--generate-config');
    if (cfgIdx !== -1 && rawArgs[cfgIdx + 1] && !rawArgs[cfgIdx + 1].startsWith('-')) {
      client = rawArgs[cfgIdx + 1];
    } else if (commandArg) {
      client = commandArg;
    }

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

  // 2. Automated Adversarial Exploit Test: exploit-test | --exploit-test
  if (command === 'exploit-test') {
    let targetTool = 'read_file';
    const expIdx = rawArgs.indexOf('--exploit-test');
    if (expIdx !== -1 && rawArgs[expIdx + 1] && !rawArgs[expIdx + 1].startsWith('-')) {
      targetTool = rawArgs[expIdx + 1];
    } else if (toolFromFlag) {
      targetTool = toolFromFlag;
    } else if (commandArg) {
      targetTool = commandArg;
    }

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

  // 3. External Server Stdio Proxy Tunnel: proxy | --proxy
  if (command === 'proxy') {
    if (!upstreamCommand) {
      console.error('❌ Error: --proxy requires an upstream command string (e.g. --proxy "npx -y @modelcontextprotocol/server-filesystem /tmp")');
      process.exit(1);
    }
    const server = new AegisProxyServer({
      upstreamCommand,
      upstreamOptions: {
        autoRestart: supervise || maxRetries > 0,
        maxRetries: maxRetries > 0 ? maxRetries : 3
      }
    });
    server.firewall.setMode(mode);
    const shutdown = () => {
      try { server.stop(); } catch {}
      process.exit(0);
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
    await server.startStdio();
    return;
  }

  // 4. Standard Stdio Gateway: stdio | --stdio
  if (command === 'stdio') {
    const server = new AegisProxyServer();
    server.firewall.setMode(mode);
    const shutdown = () => {
      try { server.stop(); } catch {}
      process.exit(0);
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
    await server.startStdio();
    return;
  }

  // 5. Dynamic Rule Synthesizer: synthesize | --synthesize
  if (command === 'synthesize') {
    let targetTool = 'read_file';
    const synIdx = rawArgs.indexOf('--synthesize');
    if (synIdx !== -1 && rawArgs[synIdx + 1] && !rawArgs[synIdx + 1].startsWith('-')) {
      targetTool = rawArgs[synIdx + 1];
    } else if (toolFromFlag) {
      targetTool = toolFromFlag;
    } else if (commandArg) {
      targetTool = commandArg;
    }

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

  // 6. Deep Cryptographic Forensics: forensics | --forensics
  if (command === 'forensics') {
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

  // 7. Web Studio & Gateway: serve | --serve
  if (command === 'serve') {
    const server = new AegisProxyServer({ port });
    server.firewall.setMode(mode);

    // Graceful signal handling
    const shutdown = () => {
      try { server.stop(); } catch {}
      process.exit(0);
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);

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

  // 8. Protocol Fuzzer: fuzz | --fuzz
  if (command === 'fuzz') {
    const targetTool = toolFromFlag || commandArg || 'read_file';

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

  // 9. Cryptographic Ledger Check: verify | --verify | --verify-ledger
  if (command === 'verify') {
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

  // 10. DAG Pipeline Execution: pipeline | --pipeline <file>
  if (command === 'pipeline') {
    let pipelinePath = null;
    const pipeIdx = rawArgs.indexOf('--pipeline');
    if (pipeIdx !== -1 && rawArgs[pipeIdx + 1] && !rawArgs[pipeIdx + 1].startsWith('-')) {
      pipelinePath = rawArgs[pipeIdx + 1];
    } else if (commandArg) {
      pipelinePath = commandArg;
    }

    if (!pipelinePath) {
      console.error('❌ Error: --pipeline requires a path to a JSON pipeline file');
      process.exit(1);
    }

    try {
      const fullPath = path.resolve(pipelinePath);
      const pipelineDef = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      console.log(`\n⛓️  Executing DAG Pipeline: "${pipelineDef.name || pipelineDef.id}" (${pipelineDef.nodes ? pipelineDef.nodes.length : 0} nodes)...\n`);

      const hub = new VirtualHub();
      const firewall = new FirewallEngine({ mode });
      const ledger = new AuditLedger();
      const dagEngine = new DAGEngine({ firewall, ledger });

      const tiers = dagEngine.resolveExecutionTiers(pipelineDef.nodes);
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
    }
  }

  // 11. Merkle Inclusion Proof Verification: verify-proof | --verify-proof <file>
  if (command === 'verify-proof') {
    let proofFile = null;
    const pIdx = rawArgs.indexOf('--verify-proof');
    if (pIdx !== -1 && rawArgs[pIdx + 1] && !rawArgs[pIdx + 1].startsWith('-')) {
      proofFile = rawArgs[pIdx + 1];
    } else if (commandArg) {
      proofFile = commandArg;
    }

    if (!proofFile) {
      console.error('❌ Error: --verify-proof requires a path to a JSON proof file');
      process.exit(1);
    }

    try {
      const { MerkleTree } = require('../src/ledger/merkleTree');
      const proofData = JSON.parse(fs.readFileSync(path.resolve(proofFile), 'utf8'));
      const { leafHash, proof, rootHash } = proofData;
      const valid = MerkleTree.verifyProof(leafHash, proof, rootHash);
      if (valid) {
        console.log(`\n✅ Merkle Inclusion Proof VERIFIED VALID: Leaf ${leafHash.slice(0, 16)}... belongs to root ${rootHash.slice(0, 16)}...`);
      } else {
        console.error(`\n❌ Merkle Inclusion Proof INVALID: Verification failed!`);
        process.exit(1);
      }
      return;
    } catch (err) {
      console.error(`❌ Proof verification error: ${err.message}`);
      process.exit(1);
    }
  }

  // 12. Adaptive Immune Red-Teaming Audit: immune-audit | --immune-audit
  if (command === 'immune-audit') {
    console.log('\n🧬 Running Autonomous Adaptive Immune Red-Teaming Audit...\n');
    const { AdaptiveImmuneLoop } = require('../src/firewall/adaptiveImmuneLoop');
    const hub = new VirtualHub();
    const firewall = new FirewallEngine({ mode });
    const ledger = new AuditLedger();
    const immune = new AdaptiveImmuneLoop();

    const audit = immune.runFullAudit(hub, firewall, ledger);
    console.log(`✅ Immune Audit Completed: ${audit.totalToolsAudited} tools audited, ${audit.results.reduce((acc, r) => acc + r.mutationsTested, 0)} mutations evaluated.`);
    const bypasses = audit.results.filter(r => r.bypassesFound > 0);
    if (bypasses.length > 0) {
      console.log(`🛡️  Auto-Remediated ${bypasses.length} potential bypasses with dynamic immune rules!`);
    } else {
      console.log('🛡️  Zero bypasses detected: all mutations neutralized by baseline zero-trust rules.');
    }
    return;
  }

  // 13. Prometheus Metrics: metrics | --metrics
  if (command === 'metrics') {
    const { PrometheusExporter } = require('../src/observability/prometheusExporter');
    const prom = new PrometheusExporter();
    const ledger = new AuditLedger();
    console.log(prom.exportMetrics({ ledger }));
    return;
  }
}

main().catch(err => {
  console.error('Fatal CLI Error:', err);
  process.exit(1);
});
