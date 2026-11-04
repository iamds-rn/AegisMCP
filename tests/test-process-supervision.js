/**
 * AegisMCP - Milestone 4 Test Suite
 * Process Supervision, Crash-Backoff Recovery, Heartbeat Probing,
 * Concurrent DAG Execution (Promise.all), and Cryptographic Tier Hashing.
 */

'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawn } = require('node:child_process');

const { ExternalProcessServer } = require('../src/servers/externalProcessServer');
const { DAGEngine, extractDependencies, interpolateValue } = require('../src/pipeline/dagEngine');
const { VirtualHub } = require('../src/servers/virtualHub');
const { FirewallEngine, MODES } = require('../src/firewall/engine');
const { AuditLedger } = require('../src/ledger/auditLedger');

const MOCK_SERVER_PATH = path.join(__dirname, 'mock-mcp-server.js');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runProcessSupervisionTests() {
  console.log('🧪 Testing Milestone 4 Process Supervision, Concurrent DAG & Health Probes...');

  // =========================================================================
  // Section 1: Process Supervision & Crash-Recovery Backoff
  // =========================================================================
  console.log('  [Section 1] Process Supervision & Crash-Recovery Backoff...');

  {
    // 1.1 Supervised start, basic tool call, and abrupt crash recovery
    const ledger = new AuditLedger();
    const server = new ExternalProcessServer({
      name: 'ext_supervised_1',
      command: 'node',
      args: [MOCK_SERVER_PATH],
      autoRestart: true,
      maxRetries: 3,
      backoffBaseMs: 50,
      maxBackoffMs: 300,
      ledger
    });

    await server.start();
    assert.strictEqual(server.status, 'CONNECTED');
    assert.strictEqual(server.isReady, true);
    assert.strictEqual(server.retryCount, 0);

    // Initial tool call works
    const res1 = await server.callTool('external_fetch_data', { query: 'alpha_query' });
    assert(res1.content[0].text.includes('alpha_query'));

    // Capture crash and recovery events
    let crashEmitted = false;
    let recoveryEmitted = false;
    server.on('crash', (info) => {
      crashEmitted = true;
      assert.strictEqual(info.serverName, 'ext_supervised_1');
    });
    server.on('recovery', (info) => {
      recoveryEmitted = true;
      assert.strictEqual(info.serverName, 'ext_supervised_1');
    });

    // Abruptly terminate the child process to simulate an external crash
    const oldPid = server.process.pid;
    server.process.kill('SIGTERM');

    // Wait for backoff and recovery (base delay: 50ms)
    await sleep(250);

    assert(crashEmitted, 'ExternalProcessServer must emit "crash" event on termination');
    assert(recoveryEmitted, 'ExternalProcessServer must emit "recovery" event after auto-restart');
    assert.strictEqual(server.status, 'CONNECTED', 'Server status must return to CONNECTED');
    assert.strictEqual(server.isReady, true, 'Server must be ready');
    assert(server.process.pid !== oldPid, 'Recovered process must have a new PID');

    // Tool call succeeds on recovered process
    const res2 = await server.callTool('external_fetch_data', { query: 'post_recovery_query' });
    assert(res2.content[0].text.includes('post_recovery_query'));

    // 1.2 Verify ledger logging on crash and recovery
    const chain = ledger.getFullChain();
    const crashBlock = chain.find(b => b.event.type === 'PROCESS_CRASH');
    const recoveryBlock = chain.find(b => b.event.type === 'PROCESS_RECOVERY');

    assert(crashBlock, 'AuditLedger must record PROCESS_CRASH event');
    assert.strictEqual(crashBlock.event.serverName, 'ext_supervised_1');
    assert.strictEqual(crashBlock.event.maxRetries, 3);

    assert(recoveryBlock, 'AuditLedger must record PROCESS_RECOVERY event');
    assert.strictEqual(recoveryBlock.event.serverName, 'ext_supervised_1');

    // Ledger cryptographic verification must be valid
    const ledgerVerif = ledger.verify();
    assert.strictEqual(ledgerVerif.valid, true, 'Audit ledger integrity must be preserved');

    // Clean shutdown
    server.stop();
    assert.strictEqual(server.status, 'STOPPED');
    assert.strictEqual(server.isReady, false);
    console.log('    ✔ Automatic crash-recovery backoff and ledger logging PASSED');
  }

  {
    // 1.3 Premature exit detection before handshake completes
    const ledger = new AuditLedger();
    const server = new ExternalProcessServer({
      name: 'ext_failing_server',
      command: 'node',
      args: ['-e', 'process.exit(1)'], // Immediately crashes on start
      autoRestart: true,
      maxRetries: 2,
      backoffBaseMs: 30,
      maxBackoffMs: 100,
      ledger
    });

    // Initial start fails because command exits immediately before handshake
    await assert.rejects(() => server.start(), /exited prematurely|exited before handshake/);

    server.stop();
    console.log('    ✔ Premature exit detection and clean stop PASSED');
  }

  {
    // 1.4 Repeated crash exhaustion during runtime and ledger logging
    const ledger = new AuditLedger();
    const server = new ExternalProcessServer({
      name: 'ext_crash_exhaust',
      command: 'node',
      args: [MOCK_SERVER_PATH],
      autoRestart: true,
      maxRetries: 2,
      backoffBaseMs: 30,
      maxBackoffMs: 100,
      ledger
    });

    await server.start();
    assert.strictEqual(server.status, 'CONNECTED');

    let exhaustedFired = false;
    server.on('restartExhausted', (info) => {
      exhaustedFired = true;
      assert.strictEqual(info.serverName, 'ext_crash_exhaust');
      assert.strictEqual(info.retryCount, 2);
    });

    // Crash 1: recovers
    server.process.kill('SIGTERM');
    await sleep(80);
    assert.strictEqual(server.status, 'CONNECTED');
    assert.strictEqual(server.retryCount, 1);

    // Crash 2: recovers
    server.process.kill('SIGTERM');
    await sleep(150);
    assert.strictEqual(server.status, 'CONNECTED');
    assert.strictEqual(server.retryCount, 2);

    // Crash 3: retries exhausted (maxRetries: 2)
    server.process.kill('SIGTERM');
    await sleep(100);

    assert.strictEqual(server.status, 'FAILED');
    assert.strictEqual(server.isReady, false);
    assert(exhaustedFired, 'Must emit restartExhausted when retry limit is reached');

    // Verify PROCESS_RESTART_EXHAUSTED logged in audit ledger
    const chain = ledger.getFullChain();
    const exhaustBlock = chain.find(b => b.event.type === 'PROCESS_RESTART_EXHAUSTED');
    assert(exhaustBlock, 'Ledger must record PROCESS_RESTART_EXHAUSTED block');
    assert.strictEqual(exhaustBlock.event.serverName, 'ext_crash_exhaust');
    assert.strictEqual(exhaustBlock.event.retryCount, 2);

    server.stop();
    console.log('    ✔ Multi-crash retry limit exhaustion (maxRetries) PASSED');
  }

  {
    // 1.5 Clean stop() does not trigger restart
    const server = new ExternalProcessServer({
      name: 'ext_clean_stop',
      command: 'node',
      args: [MOCK_SERVER_PATH],
      autoRestart: true,
      maxRetries: 3
    });

    await server.start();
    let restarted = false;
    server.on('restarting', () => { restarted = true; });

    server.stop();
    await sleep(60);

    assert.strictEqual(server.status, 'STOPPED');
    assert.strictEqual(restarted, false, 'Clean stop() MUST NOT trigger restart attempt');
    console.log('    ✔ Clean stop() suppression of restart supervision PASSED');
  }

  {
    // 1.6 Transparent recovery: tool call made during recovery window awaits readiness
    const server = new ExternalProcessServer({
      name: 'ext_transparent_recovery',
      command: 'node',
      args: [MOCK_SERVER_PATH],
      autoRestart: true,
      maxRetries: 3,
      backoffBaseMs: 60,
      maxBackoffMs: 200
    });

    await server.start();
    assert.strictEqual(server.status, 'CONNECTED');

    // Kill process to put it into crash recovery
    const crashPromise = new Promise(resolve => server.once('crash', resolve));
    server.process.kill('SIGTERM');
    await crashPromise;

    // Dispatch callTool while server is in RECOVERING state
    // callTool must await server recovery via waitForReady and succeed
    assert.strictEqual(server.status, 'RECOVERING');
    const res = await server.callTool('external_fetch_data', { query: 'transparent_recovery_test' });
    assert(res.content[0].text.includes('transparent_recovery_test'), 'Call dispatched during recovery must succeed on recovered process');
    assert.strictEqual(server.status, 'CONNECTED');

    server.stop();
    console.log('    ✔ Transparent recovery during active backoff (waitForReady) PASSED');
  }

  {
    // 1.7 JSON-RPC ID Type Coercion (numeric and string ID support)
    const server = new ExternalProcessServer({
      name: 'ext_type_coercion',
      command: 'node',
      args: [MOCK_SERVER_PATH]
    });

    await server.start();

    // Verify _getPendingRequest supports both string and number IDs
    server.pendingRequests.set(9999, { resolve: () => {}, reject: () => {}, timer: null });
    const req1 = server._getPendingRequest('9999');
    assert(req1 !== null, 'Should match string lookup on numeric ID');

    server.pendingRequests.set('8888', { resolve: () => {}, reject: () => {}, timer: null });
    const req2 = server._getPendingRequest(8888);
    assert(req2 !== null, 'Should match numeric lookup on string ID');

    server.stop();
    console.log('    ✔ JSON-RPC ID type coercion in stdio request lookup PASSED');
  }

  // =========================================================================
  // Section 2: Liveness Health Checking & Heartbeat Supervision
  // =========================================================================
  console.log('  [Section 2] Liveness Health Checking & Heartbeat Supervision...');

  {
    // 2.1 Direct ping and checkLiveness
    const server = new ExternalProcessServer({
      name: 'ext_liveness_test',
      command: 'node',
      args: [MOCK_SERVER_PATH]
    });

    await server.start();

    // ping probe
    const pingRes = await server.ping();
    assert(pingRes !== undefined, 'Ping probe must return result');

    // checkLiveness
    const liveRes = await server.checkLiveness();
    assert.strictEqual(liveRes.alive, true);
    assert.strictEqual(liveRes.pid, server.process.pid);
    assert(typeof liveRes.latencyMs === 'number');

    // Terminate process and verify checkLiveness detects failure
    server.process.kill('SIGKILL');
    await sleep(30);

    const deadRes = await server.checkLiveness();
    assert.strictEqual(deadRes.alive, false, 'checkLiveness must report false on killed process');
    assert(deadRes.error, 'Must report error description for dead process');

    server.stop();
    console.log('    ✔ Direct ping probe and liveness detection PASSED');
  }

  {
    // 2.2 Periodic heartbeat background supervision
    const ledger = new AuditLedger();
    const server = new ExternalProcessServer({
      name: 'ext_heartbeat_test',
      command: 'node',
      args: [MOCK_SERVER_PATH],
      heartbeatIntervalMs: 40,
      logHeartbeats: true,
      ledger
    });

    let heartbeatCount = 0;
    server.on('heartbeat', (data) => {
      heartbeatCount++;
      assert.strictEqual(data.serverName, 'ext_heartbeat_test');
      assert(data.timestamp > 0);
    });

    await server.start();

    // Wait for at least 3 heartbeats to fire
    await sleep(150);

    assert(heartbeatCount >= 2, `Expected at least 2 heartbeats, got ${heartbeatCount}`);
    assert(server.lastHeartbeat !== null, 'server.lastHeartbeat must be updated');

    // Verify heartbeat logged to ledger
    const chain = ledger.getFullChain();
    const hbBlocks = chain.filter(b => b.event.type === 'PROCESS_HEARTBEAT');
    assert(hbBlocks.length >= 2, 'AuditLedger must contain PROCESS_HEARTBEAT blocks');

    server.stop();
    assert.strictEqual(server.heartbeatTimer, null, 'Heartbeat timer must be cleared after stop()');
    console.log('    ✔ Periodic heartbeat background supervision & ledger recording PASSED');
  }

  {
    // 2.3 Heartbeat failure detection and ledger recording
    const ledger = new AuditLedger();
    const unresponsiveScript = 'const readline = require("readline"); const rl = readline.createInterface({ input: process.stdin, terminal: false }); rl.on("line", (l) => { const m = JSON.parse(l); if (m.method === "initialize") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05" } }) + "\\n"); if (m.method === "tools/list") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: [] } }) + "\\n"); /* ignore ping */ });';

    const server = new ExternalProcessServer({
      name: 'ext_hb_fail_test',
      command: 'node',
      args: ['-e', unresponsiveScript],
      heartbeatIntervalMs: 50,
      autoRestart: false,
      ledger
    });

    await server.start();

    const failurePromise = new Promise(resolve => server.once('heartbeatFailure', resolve));
    const failInfo = await failurePromise;
    assert.strictEqual(failInfo.serverName, 'ext_hb_fail_test');
    assert(failInfo.error.includes('Ping timeout') || failInfo.error.includes('timeout'));

    const chain = ledger.getFullChain();
    const failBlock = chain.find(b => b.event.type === 'PROCESS_HEARTBEAT_FAILED');
    assert(failBlock, 'AuditLedger must record PROCESS_HEARTBEAT_FAILED block');
    assert.strictEqual(failBlock.event.serverName, 'ext_hb_fail_test');

    server.stop();
    console.log('    ✔ Heartbeat failure detection and ledger recording PASSED');
  }

  // =========================================================================
  // Section 3: Topological Tier Concurrency in DAGEngine
  // =========================================================================
  console.log('  [Section 3] Topological Tier Concurrency in DAGEngine...');

  {
    const engine = new DAGEngine();

    // 3.1 All-independent nodes -> Single Tier 0
    const indepNodes = [
      { id: 'node_1', params: { x: 1 } },
      { id: 'node_2', params: { y: 2 } },
      { id: 'node_3', params: { z: 3 } }
    ];
    const tiers1 = engine.partitionIntoTiers(indepNodes);
    assert.strictEqual(tiers1.length, 1, 'Independent nodes must all be placed in a single tier');
    assert.strictEqual(tiers1[0].length, 3);
    assert.deepStrictEqual(tiers1[0].map(n => n.id).sort(), ['node_1', 'node_2', 'node_3']);

    // 3.2 Linear dependency chain -> 3 sequential tiers
    const chainNodes = [
      { id: 'step_3', params: { in: '{{nodes.step_2.output}}' } },
      { id: 'step_1', params: { val: 'init' } },
      { id: 'step_2', params: { in: '{{nodes.step_1.output}}' } }
    ];
    const tiers2 = engine.partitionIntoTiers(chainNodes);
    assert.strictEqual(tiers2.length, 3, 'Linear chain must yield 3 tiers');
    assert.strictEqual(tiers2[0][0].id, 'step_1');
    assert.strictEqual(tiers2[1][0].id, 'step_2');
    assert.strictEqual(tiers2[2][0].id, 'step_3');

    // 3.3 Diamond DAG -> Tier 0: [A], Tier 1: [B, C], Tier 2: [D]
    const diamondNodes = [
      { id: 'node_d', params: { b: '{{nodes.node_b.output}}', c: '{{nodes.node_c.output}}' } },
      { id: 'node_b', params: { a: '{{nodes.node_a.output}}' } },
      { id: 'node_c', params: { a: '{{nodes.node_a.output}}' } },
      { id: 'node_a', params: { init: true } }
    ];
    const tiers3 = engine.partitionIntoTiers(diamondNodes);
    assert.strictEqual(tiers3.length, 3, 'Diamond DAG must yield 3 tiers');
    assert.deepStrictEqual(tiers3[0].map(n => n.id), ['node_a']);
    assert.deepStrictEqual(tiers3[1].map(n => n.id).sort(), ['node_b', 'node_c']);
    assert.deepStrictEqual(tiers3[2].map(n => n.id), ['node_d']);

    // 3.4 Cycle detection
    const cyclic = [
      { id: 'ca', params: { in: '{{nodes.cb.out}}' } },
      { id: 'cb', params: { in: '{{nodes.ca.out}}' } }
    ];
    assert.throws(() => engine.partitionIntoTiers(cyclic), /Cyclic dependency detected/);

    // 3.5 Unknown dependency
    const unknownDep = [
      { id: 'valid_1', params: { in: '{{nodes.non_existent_node.out}}' } }
    ];
    assert.throws(() => engine.partitionIntoTiers(unknownDep), /depends on unknown node/);

    console.log('    ✔ Topological tier partitioning and cycle detection unit tests PASSED');
  }

  {
    // 3.6 Concurrency and Wall-Clock Timing Verification (Promise.all)
    const engine = new DAGEngine();

    // 3 parallel tasks in Tier 0, each sleeping for 60ms
    // Sequential execution would require 180ms
    // Parallel execution should complete in ~60-90ms
    const parallelPipeline = {
      id: 'parallel-perf-check',
      nodes: [
        { id: 'sleep_a', server: 'mock', tool: 'delay', params: { ms: 60 } },
        { id: 'sleep_b', server: 'mock', tool: 'delay', params: { ms: 60 } },
        { id: 'sleep_c', server: 'mock', tool: 'delay', params: { ms: 60 } }
      ]
    };

    const invoker = async (server, tool, params) => {
      await sleep(params.ms || 60);
      return { content: [{ type: 'text', text: JSON.stringify({ done: true, id: params.ms }) }] };
    };

    const tStart = Date.now();
    const result = await engine.executePipeline(parallelPipeline, invoker);
    const wallClock = Date.now() - tStart;

    assert.strictEqual(result.status, 'COMPLETED');
    assert.strictEqual(result.stepsExecuted, 3);
    assert.strictEqual(result.tiersExecuted, 1);
    assert.strictEqual(result.tierExecutions[0].nodeCount, 3);

    // Total wall-clock time must be significantly less than 150ms
    assert(wallClock < 130, `Expected parallel wall-clock < 130ms, got ${wallClock}ms`);
    console.log(`    ✔ Concurrent tier parallel execution confirmed (${wallClock}ms for 3x60ms tasks, expected <130ms) PASSED`);
  }

  {
    // 3.7 Per-Tier Wall-Clock Durations & Cryptographic Ledger Hashing
    const ledger = new AuditLedger();
    const engine = new DAGEngine({ ledger });

    const complexPipeline = {
      id: 'crypto-tiered-pipeline',
      name: 'Tiered Cryptographic Pipeline',
      nodes: [
        // Tier 0: 2 independent sources
        { id: 'source_1', server: 'srv', tool: 'gen', params: { val: 'alpha' } },
        { id: 'source_2', server: 'srv', tool: 'gen', params: { val: 'beta' } },
        // Tier 1: 2 parallel processors
        { id: 'proc_1', server: 'srv', tool: 'proc', params: { in: '{{nodes.source_1.output.val}}' } },
        { id: 'proc_2', server: 'srv', tool: 'proc', params: { in: '{{nodes.source_2.output.val}}' } },
        // Tier 2: 1 aggregator
        { id: 'aggregate', server: 'srv', tool: 'combine', params: { a: '{{nodes.proc_1.output.res}}', b: '{{nodes.proc_2.output.res}}' } }
      ]
    };

    const invoker = async (srv, tool, params) => {
      if (tool === 'gen') return { content: [{ type: 'text', text: JSON.stringify({ val: params.val }) }] };
      if (tool === 'proc') return { content: [{ type: 'text', text: JSON.stringify({ res: `${params.in}_processed` }) }] };
      if (tool === 'combine') return { content: [{ type: 'text', text: JSON.stringify({ combined: `${params.a}+${params.b}` }) }] };
      return {};
    };

    const result = await engine.executePipeline(complexPipeline, invoker);

    assert.strictEqual(result.status, 'COMPLETED');
    assert.strictEqual(result.stepsExecuted, 5);
    assert.strictEqual(result.tiersExecuted, 3);
    assert.strictEqual(result.tierExecutions.length, 3);

    // Verify tier execution metrics
    assert.strictEqual(result.tierExecutions[0].nodeCount, 2);
    assert.strictEqual(result.tierExecutions[1].nodeCount, 2);
    assert.strictEqual(result.tierExecutions[2].nodeCount, 1);

    for (const te of result.tierExecutions) {
      assert(typeof te.durationMs === 'number', 'Tier must record durationMs');
      assert.strictEqual(typeof te.tierHash, 'string', 'Tier must record SHA-256 tierHash');
      assert.strictEqual(te.tierHash.length, 64, 'tierHash must be 64-character hex string');
    }

    // Verify ledger contains PIPELINE_TIER_COMPLETED entries with matching hashes
    const chain = ledger.getFullChain();
    const tierBlocks = chain.filter(b => b.event.type === 'PIPELINE_TIER_COMPLETED');
    assert.strictEqual(tierBlocks.length, 3, 'Ledger must contain 3 PIPELINE_TIER_COMPLETED records');

    for (let i = 0; i < 3; i++) {
      assert.strictEqual(tierBlocks[i].event.tierIndex, i);
      assert.strictEqual(tierBlocks[i].event.tierHash, result.tierExecutions[i].tierHash);
    }

    // Verify complete ledger cryptographic integrity
    const verif = ledger.verify();
    assert.strictEqual(verif.valid, true, 'Cryptographic audit ledger must verify cleanly');
    console.log('    ✔ Per-tier wall-clock durations and cryptographic ledger hashing PASSED');
  }

  {
    // 3.8 Security Firewall Interception in Concurrent DAG Layer
    const firewall = new FirewallEngine({ mode: MODES.ENFORCE });
    const ledger = new AuditLedger();
    const engine = new DAGEngine({ firewall, ledger });

    const maliciousPipeline = {
      id: 'malicious-pipeline',
      nodes: [
        { id: 'benign_1', server: 'srv', tool: 'read_file', params: { path: '/workspace/safe.txt' } },
        { id: 'malicious_1', server: 'srv', tool: 'read_file', params: { path: '../../../../etc/shadow' } }
      ]
    };

    const invoker = async () => ({ content: [{ type: 'text', text: 'data' }] });

    await assert.rejects(
      () => engine.executePipeline(maliciousPipeline, invoker),
      /Security Policy Blocked: \[SEC-001\]/
    );

    // Verify failed step is logged in ledger
    const chain = ledger.getFullChain();
    const failBlock = chain.find(b => b.event.type === 'PIPELINE_STEP_FAILED');
    assert(failBlock, 'PIPELINE_STEP_FAILED must be recorded in ledger on firewall interception');

    const verif = ledger.verify();
    assert.strictEqual(verif.valid, true, 'Audit ledger remains intact after blocked pipeline step');
    console.log('    ✔ Security firewall interception & error halting in concurrent tier PASSED');
  }

  {
    // 3.9 Explicit dependsOn and dependencies array partitioning
    const engine = new DAGEngine();
    const explicitNodes = [
      { id: 'task_c', dependsOn: ['task_b'], params: { action: 'finish' } },
      { id: 'task_a', params: { action: 'start' } },
      { id: 'task_b', dependencies: ['task_a'], params: { action: 'process' } }
    ];

    const tiers = engine.partitionIntoTiers(explicitNodes);
    assert.strictEqual(tiers.length, 3, 'Explicit dependsOn must create 3 sequential tiers');
    assert.strictEqual(tiers[0][0].id, 'task_a');
    assert.strictEqual(tiers[1][0].id, 'task_b');
    assert.strictEqual(tiers[2][0].id, 'task_c');
    console.log('    ✔ Explicit dependsOn and dependencies array partitioning PASSED');
  }

  {
    // 3.10 MCP specification tool error (isError: true) halting concurrent tier
    const ledger = new AuditLedger();
    const engine = new DAGEngine({ ledger });

    const failingPipeline = {
      id: 'tool-error-pipeline',
      nodes: [
        { id: 'failing_tool_step', server: 'srv', tool: 'broken_action', params: {} }
      ]
    };

    // Invoker returns MCP error response with isError: true
    const invoker = async () => ({
      isError: true,
      content: [{ type: 'text', text: 'Database disk full (-32000)' }]
    });

    await assert.rejects(
      () => engine.executePipeline(failingPipeline, invoker),
      /Tool execution error: Database disk full/
    );

    const chain = ledger.getFullChain();
    const failedBlock = chain.find(b => b.event.type === 'PIPELINE_STEP_FAILED');
    assert(failedBlock, 'Must record PIPELINE_STEP_FAILED when tool returns isError: true');
    assert(failedBlock.event.error.includes('Database disk full'));

    console.log('    ✔ MCP tool error (isError: true) halting & ledger logging PASSED');
  }

  // =========================================================================
  // Section 4: Integration with VirtualHub & CLI Automation
  // =========================================================================
  console.log('  [Section 4] Integration with VirtualHub & CLI Automation...');

  {
    // 4.1 Supervised External Server inside VirtualHub
    const hub = new VirtualHub();
    const ledger = new AuditLedger();

    const extServer = await hub.registerExternalServer({
      name: 'ext_in_hub',
      command: 'node',
      args: [MOCK_SERVER_PATH],
      autoRestart: true,
      maxRetries: 3,
      backoffBaseMs: 50,
      ledger
    });

    const call1 = await hub.executeTool('ext_in_hub', 'external_fetch_data', { query: 'hub_test_1' });
    assert(call1.content[0].text.includes('hub_test_1'));

    // Crash it and wait for auto-recovery
    extServer.process.kill('SIGTERM');
    await sleep(200);

    assert.strictEqual(extServer.status, 'CONNECTED');

    // Call tool again through VirtualHub on recovered process
    const call2 = await hub.executeTool('ext_in_hub', 'external_fetch_data', { query: 'hub_test_2' });
    assert(call2.content[0].text.includes('hub_test_2'));

    hub.shutdownAll();
    console.log('    ✔ Supervised external server in VirtualHub with transparent recovery PASSED');
  }

  {
    // 4.2 CLI Automation: aegis-mcp --pipeline <file>
    const tmpDir = os.tmpdir();
    const tmpPipelinePath = path.join(tmpDir, `aegis-test-pipeline-${Date.now()}.json`);

    const samplePipeline = {
      id: 'cli-test-dag',
      name: 'CLI Automated Pipeline',
      nodes: [
        { id: 'step_token', server: 'virtual_crypto', tool: 'generate_token', params: { bytes: 8, format: 'hex' } },
        { id: 'step_hash', server: 'virtual_crypto', tool: 'hash_sha256', params: { text: '{{nodes.step_token.output.token}}' } }
      ]
    };

    fs.writeFileSync(tmpPipelinePath, JSON.stringify(samplePipeline, null, 2), 'utf8');

    try {
      const cliPath = path.resolve(__dirname, '../bin/aegis-mcp.js');
      const stdout = await new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [cliPath, '--pipeline', tmpPipelinePath], {
          stdio: ['pipe', 'pipe', 'pipe']
        });
        let out = '';
        let err = '';
        child.stdout.on('data', chunk => { out += chunk; });
        child.stderr.on('data', chunk => { err += chunk; });
        child.on('close', code => {
          if (code === 0) resolve(out);
          else reject(new Error(`CLI exited with code ${code}: ${err}`));
        });
        child.on('error', reject);
      });

      assert(stdout.includes('Executing DAG Pipeline: "CLI Automated Pipeline"'), 'CLI should announce pipeline execution');
      assert(stdout.includes('Topological Partitioning: 2 concurrent execution tiers'), 'CLI should report tiers');
      assert(stdout.includes('COMPLETED'), 'CLI output must report COMPLETED');
      assert(stdout.includes('SHA-256 Hash:'), 'CLI output must report per-tier SHA-256 cryptographic hashes');
      console.log('    ✔ CLI Automation (aegis-mcp --pipeline <file>) execution PASSED');
    } finally {
      try { fs.unlinkSync(tmpPipelinePath); } catch {}
    }
  }

  console.log('✅ Milestone 4: All process supervision, DAG tier concurrency, and CLI automation tests passed!');
}

module.exports = { runProcessSupervisionTests };

if (require.main === module) {
  runProcessSupervisionTests().catch(err => {
    console.error('Test Process Supervision Failed:', err);
    process.exit(1);
  });
}
