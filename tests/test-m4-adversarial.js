/**
 * AegisMCP - Milestone 4 Empirical Adversarial Challenge Suite
 *
 * Rigorous empirical stress-testing and boundary verification for:
 * 1. tokenizeCommand shell tokenizer edge cases (quotes, spaces, escapes)
 * 2. ExternalProcessServer repeated sudden crash (SIGKILL) auto-restart & backoff
 * 3. ExternalProcessServer stubborn process SIGTERM ignore -> SIGKILL escalation
 * 4. ExternalProcessServer stdio write backpressure with burst payloads (>128 KB)
 * 5. DAGEngine concurrent tier execution (Diamond, Multi-branch, max(T_i) vs sum(T_i))
 * 6. DAGEngine MCP tool error inspection (isError: true, fallback, abortOnError: false)
 */

'use strict';

const assert = require('node:assert');
const path = require('node:path');
const { ExternalProcessServer, tokenizeCommand } = require('../src/servers/externalProcessServer');
const { DAGEngine } = require('../src/pipeline/dagEngine');
const { AuditLedger } = require('../src/ledger/auditLedger');

const MOCK_SERVER_PATH = path.join(__dirname, 'mock-mcp-server.js');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runAdversarialM4Tests() {
  console.log('🥊 ==============================================================');
  console.log('   AEGIS-MCP MILESTONE 4 EMPIRICAL ADVERSARIAL CHALLENGE SUITE');
  console.log('==============================================================');

  // =========================================================================
  // Challenge 1: tokenizeCommand Edge Cases & Boundary Conditions
  // =========================================================================
  console.log('\n[Challenge 1] Testing tokenizeCommand Edge Cases & Boundary Conditions...');
  {
    // 1.1 Consecutive whitespace & trimming
    assert.deepStrictEqual(tokenizeCommand('cmd    arg1    arg2   arg3'), ['cmd', 'arg1', 'arg2', 'arg3']);
    assert.deepStrictEqual(tokenizeCommand('   leading and trailing   '), ['leading', 'and', 'trailing']);
    assert.deepStrictEqual(tokenizeCommand('   \t  \n  '), []);
    assert.deepStrictEqual(tokenizeCommand(''), []);
    assert.deepStrictEqual(tokenizeCommand(null), []);
    assert.deepStrictEqual(tokenizeCommand(undefined), []);

    // 1.2 Empty quotes preserves empty string token
    assert.deepStrictEqual(tokenizeCommand('""'), ['']);
    assert.deepStrictEqual(tokenizeCommand("''"), ['']);
    assert.deepStrictEqual(tokenizeCommand('cmd ""'), ['cmd', '']);
    assert.deepStrictEqual(tokenizeCommand("cmd ''"), ['cmd', '']);
    assert.deepStrictEqual(tokenizeCommand('cmd "" "" \'\' \'\''), ['cmd', '', '', '', '']);
    assert.deepStrictEqual(tokenizeCommand('echo "" middle "" end'), ['echo', '', 'middle', '', 'end']);

    // 1.3 Escaped quotes and backslashes
    assert.deepStrictEqual(
      tokenizeCommand('cmd "arg with \\"escaped\\" quotes"'),
      ['cmd', 'arg with "escaped" quotes']
    );
    assert.deepStrictEqual(
      tokenizeCommand('cmd \\"outside\\"'),
      ['cmd', '"outside"']
    );
    assert.deepStrictEqual(
      tokenizeCommand('cmd "nested \\\\ backslash"'),
      ['cmd', 'nested \\ backslash']
    );
    assert.deepStrictEqual(
      tokenizeCommand('cmd "quote at end\\""'),
      ['cmd', 'quote at end"']
    );

    // 1.4 Mixed quotes and shell-style adjacent concatenations
    assert.deepStrictEqual(
      tokenizeCommand('cmd "double with \'single\' inside"'),
      ['cmd', "double with 'single' inside"]
    );
    assert.deepStrictEqual(
      tokenizeCommand("cmd 'single with \"double\" inside'"),
      ['cmd', 'single with "double" inside']
    );
    assert.deepStrictEqual(
      tokenizeCommand('cmd "hello"\'world\''),
      ['cmd', 'helloworld']
    );
    assert.deepStrictEqual(
      tokenizeCommand('cmd "foo bar"\' baz qux\''),
      ['cmd', 'foo bar baz qux']
    );

    // 1.5 Unbalanced quotes degrade gracefully
    assert.deepStrictEqual(tokenizeCommand('cmd "unclosed double quote'), ['cmd', 'unclosed double quote']);
    assert.deepStrictEqual(tokenizeCommand("cmd 'unclosed single quote"), ['cmd', 'unclosed single quote']);

    console.log('  ✔ Challenge 1: tokenizeCommand 17 edge-case assertions PASSED');
  }

  // =========================================================================
  // Challenge 2: Repeated Sudden Crashes (SIGKILL) & Auto-Restart Recovery
  // =========================================================================
  console.log('\n[Challenge 2] Testing Repeated Sudden Crashes (SIGKILL) & Auto-Restart...');
  {
    const ledger = new AuditLedger();
    const server = new ExternalProcessServer({
      name: 'adv_sigkill_server',
      command: 'node',
      args: [MOCK_SERVER_PATH],
      autoRestart: true,
      maxRestarts: 3,
      restartDelayMs: 40,
      maxBackoffMs: 250,
      ledger
    });

    // Verify option aliases maxRestarts / restartDelayMs
    assert.strictEqual(server.maxRetries, 3);
    assert.strictEqual(server.maxRestarts, 3);
    assert.strictEqual(server.backoffBaseMs, 40);
    assert.strictEqual(server.restartDelayMs, 40);

    await server.start();
    const initialPid = server.process.pid;
    assert.strictEqual(server.status, 'CONNECTED');

    // Tool call succeeds before crashes
    const initialCall = await server.callTool('external_fetch_data', { query: 'init' });
    assert(initialCall.content[0].text.includes('init'));

    // Perform 2 consecutive sudden SIGKILLs
    for (let cycle = 1; cycle <= 2; cycle++) {
      const priorPid = server.process.pid;
      const crashPromise = new Promise(resolve => server.once('crash', resolve));
      const recoveryPromise = new Promise(resolve => server.once('recovery', resolve));

      // Immediate kernel termination (SIGKILL cannot be caught or ignored)
      server.process.kill('SIGKILL');

      const crashInfo = await crashPromise;
      assert.strictEqual(crashInfo.serverName, 'adv_sigkill_server');
      assert.strictEqual(crashInfo.signal, 'SIGKILL');

      const recoveryInfo = await recoveryPromise;
      assert.strictEqual(recoveryInfo.serverName, 'adv_sigkill_server');
      assert.strictEqual(recoveryInfo.retryCount, cycle);
      assert.strictEqual(server.status, 'CONNECTED');
      assert(server.process.pid !== priorPid, `Cycle ${cycle}: Process PID must change after recovery`);

      // Invoke tool call on newly recovered process
      const postRecoveryCall = await server.callTool('external_fetch_data', { query: `cycle_${cycle}` });
      assert(postRecoveryCall.content[0].text.includes(`cycle_${cycle}`));
    }

    // Verify audit ledger records all crashes and recoveries
    const chain = ledger.getFullChain();
    const crashEvents = chain.filter(b => b.event.type === 'PROCESS_CRASH');
    const recoveryEvents = chain.filter(b => b.event.type === 'PROCESS_RECOVERY');
    assert.strictEqual(crashEvents.length, 2, 'Ledger must contain 2 PROCESS_CRASH blocks');
    assert.strictEqual(recoveryEvents.length, 2, 'Ledger must contain 2 PROCESS_RECOVERY blocks');
    assert.strictEqual(ledger.verify().valid, true, 'Audit ledger hash chain must verify valid');

    server.stop();
    assert.strictEqual(server.status, 'STOPPED');
    console.log('  ✔ Challenge 2: Repeated SIGKILL auto-restart & transparent recovery PASSED');
  }

  // =========================================================================
  // Challenge 3: Stubborn Process Ignoring SIGTERM -> SIGKILL Escalation
  // =========================================================================
  console.log('\n[Challenge 3] Testing Stubborn Process SIGTERM Ignore -> SIGKILL Escalation...');
  {
    // Mock child process that explicitly traps and ignores SIGTERM and maintains active event loop
    const stubbornScript = `
      const readline = require('readline');
      const rl = readline.createInterface({ input: process.stdin });
      rl.on('line', (line) => {
        try {
          const msg = JSON.parse(line);
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

      // Stubbornly ignore SIGTERM
      process.on('SIGTERM', () => {
        // Intentionally no-op to resist termination
      });
      // Keep event loop alive
      const keepAlive = setInterval(() => {}, 10000);
      process.on('exit', () => clearInterval(keepAlive));
    `;

    const server = new ExternalProcessServer({
      name: 'adv_stubborn_server',
      command: 'node',
      args: ['-e', stubbornScript],
      autoRestart: false
    });

    await server.start();
    const childProc = server.process;
    assert(childProc && childProc.pid, 'Stubborn child process must be running');

    const gracePeriodMs = 300;
    const tStart = Date.now();

    let exitCode = null;
    let exitSignal = null;
    const exitPromise = new Promise(resolve => {
      childProc.once('exit', (code, signal) => {
        exitCode = code;
        exitSignal = signal;
        resolve();
      });
    });

    // Request stop with 300ms grace period
    server.stop(gracePeriodMs);

    await exitPromise;
    const elapsedMs = Date.now() - tStart;

    // Verify escalation invariants
    assert.strictEqual(exitSignal, 'SIGKILL', `Process must be terminated by SIGKILL, got: ${exitSignal}`);
    assert(
      elapsedMs >= gracePeriodMs - 50,
      `Escalation must not happen prematurely: elapsed ${elapsedMs}ms < grace ${gracePeriodMs}ms`
    );
    assert(
      elapsedMs <= gracePeriodMs + 400,
      `Escalation must terminate process reasonably after grace period: elapsed ${elapsedMs}ms`
    );

    console.log(`  ✔ Challenge 3: Stubborn process terminated by SIGKILL after ${elapsedMs}ms (~${gracePeriodMs}ms grace) PASSED`);
  }

  // =========================================================================
  // Challenge 4: Stdio Write Backpressure with Burst Payloads (>128 KB)
  // =========================================================================
  console.log('\n[Challenge 4] Testing Stdio Write Backpressure with Burst Payloads (>128 KB)...');
  {
    // Mock server echoing payload size and sha256 to verify integrity
    const backpressureServerScript = `
      const crypto = require('crypto');
      const readline = require('readline');
      const rl = readline.createInterface({ input: process.stdin, terminal: false });

      rl.on('line', (line) => {
        try {
          const msg = JSON.parse(line);
          if (msg.method === 'initialize') {
            process.stdout.write(JSON.stringify({
              jsonrpc: '2.0',
              id: msg.id,
              result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'bp', version: '1.0' } }
            }) + '\\n');
            return;
          }
          if (msg.method === 'tools/list') {
            process.stdout.write(JSON.stringify({
              jsonrpc: '2.0',
              id: msg.id,
              result: { tools: [{ name: 'echo_payload', description: 'Echo payload metrics', inputSchema: {} }] }
            }) + '\\n');
            return;
          }
          if (msg.method === 'tools/call') {
            const data = (msg.params && msg.params.arguments) ? msg.params.arguments.data : '';
            const hash = crypto.createHash('sha256').update(data).digest('hex');
            process.stdout.write(JSON.stringify({
              jsonrpc: '2.0',
              id: msg.id,
              result: {
                content: [{
                  type: 'text',
                  text: JSON.stringify({ byteLength: Buffer.byteLength(data, 'utf8'), hash })
                }]
              }
            }) + '\\n');
          }
        } catch {}
      });
    `;

    const server = new ExternalProcessServer({
      name: 'adv_backpressure_server',
      command: 'node',
      args: ['-e', backpressureServerScript],
      autoRestart: false
    });

    await server.start();

    // Track 'drain' events on process stdin
    let drainEvents = 0;
    server.process.stdin.on('drain', () => {
      drainEvents++;
    });

    // 200 KB per payload, 6 concurrent bursts = 1.2 MB total burst
    const crypto = require('node:crypto');
    const payloadSize = 200 * 1024;
    const rawPayload = 'Z'.repeat(payloadSize);
    const expectedHash = crypto.createHash('sha256').update(rawPayload).digest('hex');
    const burstCount = 6;

    const burstPromises = [];
    for (let i = 0; i < burstCount; i++) {
      burstPromises.push(server.callTool('echo_payload', { data: rawPayload, seq: i }));
    }

    const results = await Promise.all(burstPromises);
    assert.strictEqual(results.length, burstCount);

    for (let i = 0; i < results.length; i++) {
      const parsed = JSON.parse(results[i].content[0].text);
      assert.strictEqual(parsed.byteLength, payloadSize, `Request ${i} payload length mismatch`);
      assert.strictEqual(parsed.hash, expectedHash, `Request ${i} cryptographic hash mismatch`);
    }

    // Verify drain handling was actually engaged
    assert(drainEvents > 0, `Expected backpressure drain events to fire (>0), got: ${drainEvents}`);

    server.stop();
    console.log(`  ✔ Challenge 4: Backpressure burst test (${burstCount}x200KB = 1.2MB, ${drainEvents} drain events) PASSED`);
  }

  // =========================================================================
  // Challenge 5: DAGEngine Concurrent Tier Execution & Wall-Clock Timing
  // =========================================================================
  console.log('\n[Challenge 5] Testing DAGEngine Concurrent Tier Execution & Wall-Clock Timing...');
  {
    const engine = new DAGEngine();

    // 5.1 Diamond DAG:
    //      A (30ms)
    //     / \
    //    B   C (each 80ms, Tier 1 parallel)
    //     \ /
    //      D (30ms)
    // Sum of times: 30 + 80 + 80 + 30 = 220ms
    // Concurrent time: 30 + 80 + 30 = 140ms
    const diamondPipeline = {
      id: 'diamond-dag',
      nodes: [
        { id: 'node_a', server: 'mock', tool: 'step', params: { delay: 30, val: 10 } },
        { id: 'node_b', server: 'mock', tool: 'step', params: { delay: 80, in: '{{nodes.node_a.output.val}}' } },
        { id: 'node_c', server: 'mock', tool: 'step', params: { delay: 80, in: '{{nodes.node_a.output.val}}' } },
        { id: 'node_d', server: 'mock', tool: 'step', params: { delay: 30, b: '{{nodes.node_b.output.val}}', c: '{{nodes.node_c.output.val}}' } }
      ]
    };

    const invoker = async (server, tool, params) => {
      await sleep(params.delay);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ val: (params.in || 0) + (params.b || 0) + (params.c || 0) + 1 })
        }]
      };
    };

    const diamondStart = Date.now();
    const diamondRes = await engine.executePipeline(diamondPipeline, invoker);
    const diamondDuration = Date.now() - diamondStart;

    assert.strictEqual(diamondRes.status, 'COMPLETED');
    assert.strictEqual(diamondRes.tiersExecuted, 3);
    assert.strictEqual(diamondRes.tierExecutions[1].nodeCount, 2);
    // Tier 1 took ~80ms, significantly less than 80+80=160ms
    assert(diamondRes.tierExecutions[1].durationMs < 140, `Tier 1 duration ${diamondRes.tierExecutions[1].durationMs}ms must be < 140ms`);
    assert(diamondDuration < 200, `Diamond total wall clock ${diamondDuration}ms must be < 200ms`);

    // 5.2 Multi-branch 5-wide concurrent DAG:
    // Root (30ms) -> 5 parallel workers (each 100ms) -> Aggregator (30ms)
    // Sum: 30 + 500 + 30 = 560ms
    // Concurrent: 30 + 100 + 30 = 160ms
    const widePipeline = {
      id: 'wide-dag',
      nodes: [
        { id: 'root', server: 'mock', tool: 'step', params: { delay: 30 } },
        { id: 'w1', server: 'mock', tool: 'step', params: { delay: 100, p: '{{nodes.root.output.val}}' } },
        { id: 'w2', server: 'mock', tool: 'step', params: { delay: 100, p: '{{nodes.root.output.val}}' } },
        { id: 'w3', server: 'mock', tool: 'step', params: { delay: 100, p: '{{nodes.root.output.val}}' } },
        { id: 'w4', server: 'mock', tool: 'step', params: { delay: 100, p: '{{nodes.root.output.val}}' } },
        { id: 'w5', server: 'mock', tool: 'step', params: { delay: 100, p: '{{nodes.root.output.val}}' } },
        { id: 'agg', server: 'mock', tool: 'step', params: {
            delay: 30,
            w1: '{{nodes.w1.output.val}}',
            w2: '{{nodes.w2.output.val}}',
            w3: '{{nodes.w3.output.val}}',
            w4: '{{nodes.w4.output.val}}',
            w5: '{{nodes.w5.output.val}}'
          }
        }
      ]
    };

    const wideStart = Date.now();
    const wideRes = await engine.executePipeline(widePipeline, invoker);
    const wideDuration = Date.now() - wideStart;

    assert.strictEqual(wideRes.status, 'COMPLETED');
    assert.strictEqual(wideRes.stepsExecuted, 7);
    assert.strictEqual(wideRes.tiersExecuted, 3);
    assert.strictEqual(wideRes.tierExecutions[1].nodeCount, 5);
    // Tier 1 of 5 x 100ms tasks finished in ~100ms, not 500ms
    assert(wideRes.tierExecutions[1].durationMs < 160, `5-worker tier duration ${wideRes.tierExecutions[1].durationMs}ms must be < 160ms`);
    assert(wideDuration < 270, `Wide pipeline duration ${wideDuration}ms must be << sum(T_i) 560ms`);

    console.log(`  ✔ Challenge 5: Diamond (${diamondDuration}ms) & 5-wide DAG (${wideDuration}ms vs 560ms sum) PASSED`);
  }

  // =========================================================================
  // Challenge 6: Tool Error Inspection, Fallback, and Abort Policies
  // =========================================================================
  console.log('\n[Challenge 6] Testing Tool Error Inspection, Fallback, and Abort Policies...');
  {
    const ledger = new AuditLedger();
    const engine = new DAGEngine({ ledger });

    // 6.1 Tool returning { isError: true } with node.fallback
    const fallbackPipeline = {
      id: 'tool-error-fallback',
      nodes: [
        {
          id: 'step_err_fallback',
          server: 'api',
          tool: 'external_lookup',
          params: { id: 101 },
          fallback: { cached: true, value: 'fallback_payload_xyz' }
        },
        {
          id: 'step_consumer',
          server: 'api',
          tool: 'format',
          params: { data: '{{nodes.step_err_fallback.output.value}}' }
        }
      ]
    };

    const invokerWithErrors = async (server, tool, params) => {
      if (tool === 'external_lookup') {
        return {
          isError: true,
          content: [{ type: 'text', text: 'Downstream microservice unreachable (HTTP 502)' }]
        };
      }
      if (tool === 'format') {
        return {
          content: [{ type: 'text', text: JSON.stringify({ formatted: params.data.toUpperCase() }) }]
        };
      }
      return {};
    };

    const resFallback = await engine.executePipeline(fallbackPipeline, invokerWithErrors);
    assert.strictEqual(resFallback.status, 'COMPLETED');
    assert.strictEqual(resFallback.finalOutputs['step_err_fallback'].status, 'FALLBACK');
    assert.strictEqual(resFallback.finalOutputs['step_err_fallback'].output.cached, true);
    assert.strictEqual(resFallback.finalOutputs['step_consumer'].status, 'SUCCESS');
    assert.strictEqual(resFallback.finalOutputs['step_consumer'].output.formatted, 'FALLBACK_PAYLOAD_XYZ');

    // 6.2 Tool returning { isError: true } with abortOnError: false
    const nonFatalPipeline = {
      id: 'tool-error-nonfatal',
      nodes: [
        { id: 'first_ok', server: 'core', tool: 'format', params: { data: 'base' } },
        { id: 'optional_fail', server: 'core', tool: 'external_lookup', params: {}, abortOnError: false },
        { id: 'last_ok', server: 'core', tool: 'format', params: { data: 'final' } }
      ]
    };

    const resNonFatal = await engine.executePipeline(nonFatalPipeline, invokerWithErrors);
    assert.strictEqual(resNonFatal.status, 'COMPLETED');
    assert.strictEqual(resNonFatal.finalOutputs['first_ok'].status, 'SUCCESS');
    assert.strictEqual(resNonFatal.finalOutputs['optional_fail'].status, 'FAILED');
    assert(resNonFatal.finalOutputs['optional_fail'].error.includes('HTTP 502'));
    assert.strictEqual(resNonFatal.finalOutputs['last_ok'].status, 'SUCCESS');

    // 6.3 Tool returning { isError: true } with default abort policy (throws and halts)
    const fatalPipeline = {
      id: 'tool-error-fatal',
      nodes: [
        { id: 'fatal_node', server: 'core', tool: 'external_lookup', params: {} },
        { id: 'unreached_node', server: 'core', tool: 'format', params: { data: 'test' } }
      ]
    };

    await assert.rejects(
      () => engine.executePipeline(fatalPipeline, invokerWithErrors),
      /Tool execution error: Downstream microservice unreachable/
    );

    // 6.4 Verification of Audit Ledger event generation for fallback & failure
    const chain = ledger.getFullChain();
    const fallbackBlock = chain.find(b => b.event.type === 'PIPELINE_STEP_FALLBACK');
    const failedBlocks = chain.filter(b => b.event.type === 'PIPELINE_STEP_FAILED');

    assert(fallbackBlock, 'AuditLedger must record PIPELINE_STEP_FALLBACK');
    assert.strictEqual(fallbackBlock.event.nodeId, 'step_err_fallback');
    assert.deepStrictEqual(fallbackBlock.event.fallback, { cached: true, value: 'fallback_payload_xyz' });

    assert(failedBlocks.length >= 2, 'AuditLedger must record PIPELINE_STEP_FAILED for both failed steps');
    assert(ledger.verify().valid, 'Audit ledger cryptographic chain must verify valid');

    console.log('  ✔ Challenge 6: isError tool error inspection, fallback, and abort policies PASSED');
  }

  console.log('\n==============================================================');
  console.log('🛡️  ALL 6 ADVERSARIAL CHALLENGES COMPLETED & VERIFIED CLEANLY!');
  console.log('==============================================================\n');
}

module.exports = { runAdversarialM4Tests };

if (require.main === module) {
  runAdversarialM4Tests().catch(err => {
    console.error('Adversarial Test Failed:', err);
    process.exit(1);
  });
}
