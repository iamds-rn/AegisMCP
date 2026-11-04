/**
 * Tests for AegisMCP Visual DAG Pipeline Engine
 */

'use strict';

const assert = require('node:assert');
const { DAGEngine, extractDependencies, interpolateValue } = require('../src/pipeline/dagEngine');
const { VirtualHub } = require('../src/servers/virtualHub');
const { FirewallEngine } = require('../src/firewall/engine');
const { AuditLedger } = require('../src/ledger/auditLedger');

async function runPipelineTests() {
  console.log('🧪 Testing Visual DAG Pipeline Engine...');

  // 1. Dependency extraction (nested, direct, and spaced expressions)
  const sampleParams = {
    key: '{{nodes.step1.output.secret}}',
    nested: { ref: '{{nodes.step2.output.data.hash}}' },
    direct: '{{nodes.step3}}',
    spaced: '{{ nodes.step4.output }}',
    normal: 'literal_value'
  };
  const deps = extractDependencies(sampleParams);
  assert.deepStrictEqual(deps.sort(), ['step1', 'step2', 'step3', 'step4']);

  // 2. Value interpolation
  const context = {
    nodes: {
      step1: { output: { secret: 'alpha_key_99' } },
      step2: { output: { data: { hash: 'e3b0c442' } } },
      step3: 'direct_value_3',
      step4: { output: 'spaced_value_4' }
    }
  };
  const interpolated = interpolateValue(sampleParams, context);
  assert.strictEqual(interpolated.key, 'alpha_key_99');
  assert.strictEqual(interpolated.nested.ref, 'e3b0c442');
  assert.strictEqual(interpolated.direct, 'direct_value_3');
  assert.strictEqual(interpolated.spaced, 'spaced_value_4');
  assert.strictEqual(interpolated.normal, 'literal_value');

  // 3. Topological sort
  const engine = new DAGEngine();
  const nodes = [
    { id: 'node_c', params: { in: '{{nodes.node_b.output.x}}' } },
    { id: 'node_a', params: { in: 'root' } },
    { id: 'node_b', params: { in: '{{nodes.node_a.output.x}}' } }
  ];
  const sorted = engine.resolveExecutionOrder(nodes);
  assert.deepStrictEqual(sorted.map(n => n.id), ['node_a', 'node_b', 'node_c']);

  // 4. Cycle detection & Duplicate Node ID validation
  const cyclicNodes = [
    { id: 'cycle_1', params: { in: '{{nodes.cycle_2.output.x}}' } },
    { id: 'cycle_2', params: { in: '{{nodes.cycle_1.output.x}}' } }
  ];
  assert.throws(() => engine.resolveExecutionOrder(cyclicNodes), /Cyclic dependency detected/);

  const duplicateNodes = [
    { id: 'dup_node', params: {} },
    { id: 'dup_node', params: {} }
  ];
  assert.throws(() => engine.resolveExecutionOrder(duplicateNodes), /Duplicate node ID detected/);
  assert.throws(() => engine.resolveExecutionOrder('not-an-array'), /Pipeline nodes must be an array/);

  // 5. Full End-to-End Pipeline Execution across Virtual MCP Servers
  const hub = new VirtualHub();
  const firewall = new FirewallEngine();
  const ledger = new AuditLedger();
  const pipelineEngine = new DAGEngine({ firewall, ledger });

  const multiServerPipeline = {
    id: 'crypto-storage-pipeline',
    name: 'Secure Token Generation & Memory Audit',
    nodes: [
      {
        id: 'gen_token',
        server: 'virtual_crypto',
        tool: 'generate_token',
        params: { bytes: 16, format: 'hex' }
      },
      {
        id: 'hash_token',
        server: 'virtual_crypto',
        tool: 'hash_sha256',
        params: { text: '{{nodes.gen_token.output.token}}' }
      },
      {
        id: 'store_token_record',
        server: 'virtual_memory',
        tool: 'set_key',
        params: {
          key: 'session:active_hash',
          value: '{{nodes.hash_token.output.hash}}',
          tags: ['auth', 'crypto']
        }
      },
      {
        id: 'persist_audit_file',
        server: 'virtual_filesystem',
        tool: 'write_file',
        params: {
          path: '/workspace/security_checkpoint.txt',
          content: 'Session Hash: {{nodes.hash_token.output.hash}}'
        }
      }
    ]
  };

  const invoker = (server, tool, params) => hub.executeTool(server, tool, params);
  const result = await pipelineEngine.executePipeline(multiServerPipeline, invoker);

  assert.strictEqual(result.status, 'COMPLETED');
  assert.strictEqual(result.stepsExecuted, 4);

  // Verify memory has the stored hash
  const memoryServer = hub.getServer('virtual_memory');
  const storedEntry = JSON.parse((await memoryServer.callTool('get_key', { key: 'session:active_hash' })).content[0].text);
  assert(storedEntry.value.length === 64, 'Stored hash must be 64 characters SHA-256 hex');

  // Verify filesystem has the persisted file
  const fsServer = hub.getServer('virtual_filesystem');
  const fileContent = (await fsServer.callTool('read_file', { path: '/workspace/security_checkpoint.txt' })).content[0].text;
  assert(fileContent.includes(storedEntry.value), 'Filesystem file must contain the generated hash');

  // 6. Invalid pipeline input validation
  await assert.rejects(() => pipelineEngine.executePipeline({ id: 'invalid-pipeline' }, invoker), /Pipeline definition must contain a "nodes" array/);

  // 7. Topological Tier Grouping & Diamond DAG Resolution
  const diamondNodes = [
    { id: 'node_d', params: { in1: '{{nodes.node_b.output}}', in2: '{{nodes.node_c.output}}' } },
    { id: 'node_b', dependsOn: ['node_a'], params: {} },
    { id: 'node_c', dependencies: ['node_a'], params: {} },
    { id: 'node_a', params: { in: 'root' } }
  ];
  const diamondTiers = engine.resolveExecutionTiers(diamondNodes);
  assert.strictEqual(diamondTiers.length, 3);
  assert.deepStrictEqual(diamondTiers[0].map(n => n.id), ['node_a']);
  assert.deepStrictEqual(diamondTiers[1].map(n => n.id).sort(), ['node_b', 'node_c']);
  assert.deepStrictEqual(diamondTiers[2].map(n => n.id), ['node_d']);

  const diamondOrder = engine.resolveExecutionOrder(diamondNodes);
  assert.strictEqual(diamondOrder[0].id, 'node_a');
  assert.strictEqual(diamondOrder[3].id, 'node_d');

  // 8. Concurrent Tier Execution Speedup (<90ms for 3 parallel 40ms tasks)
  const concurrentNodes = [
    { id: 't1_a', server: 'mock', tool: 'delay', params: { ms: 40 } },
    { id: 't1_b', server: 'mock', tool: 'delay', params: { ms: 40 } },
    { id: 't1_c', server: 'mock', tool: 'delay', params: { ms: 40 } }
  ];
  const delayInvoker = async (server, tool, params) => {
    await new Promise(r => setTimeout(r, params.ms || 40));
    return { content: [{ type: 'text', text: JSON.stringify({ finished: true, id: params.id || 'ok' }) }] };
  };
  const cStart = Date.now();
  const cResult = await pipelineEngine.executePipeline({ id: 'concurrent-test', nodes: concurrentNodes }, delayInvoker);
  const cDuration = Date.now() - cStart;
  assert.strictEqual(cResult.status, 'COMPLETED');
  assert.strictEqual(cResult.stepsExecuted, 3);
  // Sequential would take >= 120ms; parallel tier should take < 90ms (and at least ~35ms)
  assert(cDuration < 90, `Concurrent tier execution should complete in <90ms, took ${cDuration}ms`);

  // 9. Tool Execution Error Inspection (MCP isError: true and JSON-RPC error)
  const errorNodes = [
    { id: 'fail_node', server: 'mock', tool: 'err', params: {} }
  ];
  const mcpErrorInvoker = async () => ({
    isError: true,
    content: [{ type: 'text', text: 'Downstream MCP service unreachable' }]
  });
  await assert.rejects(
    () => pipelineEngine.executePipeline({ id: 'err-pipe-1', nodes: errorNodes }, mcpErrorInvoker),
    /Downstream MCP service unreachable/
  );

  const rpcErrorInvoker = async () => ({
    error: { code: -32603, message: 'Internal RPC error' }
  });
  await assert.rejects(
    () => pipelineEngine.executePipeline({ id: 'err-pipe-2', nodes: errorNodes }, rpcErrorInvoker),
    /Internal RPC error/
  );

  // 10. Step Error Policy: abortOnError: false
  const nonFatalLedger = new AuditLedger();
  const nonFatalEngine = new DAGEngine({ ledger: nonFatalLedger });
  const nonFatalPipeline = {
    id: 'non-fatal-pipeline',
    nodes: [
      { id: 'step_err', server: 'mock', tool: 'bad_tool', abortOnError: false },
      { id: 'step_ok', server: 'mock', tool: 'good_tool', dependsOn: ['step_err'] }
    ]
  };
  const mixedInvoker = async (server, tool) => {
    if (tool === 'bad_tool') throw new Error('Simulated transient failure');
    return { content: [{ type: 'text', text: JSON.stringify({ status: 'ok' }) }] };
  };
  const nonFatalRes = await nonFatalEngine.executePipeline(nonFatalPipeline, mixedInvoker);
  assert.strictEqual(nonFatalRes.status, 'COMPLETED');
  assert.strictEqual(nonFatalRes.context.nodes.step_err.status, 'FAILED');
  assert.strictEqual(nonFatalRes.context.nodes.step_ok.status, 'SUCCESS');
  const failedAudit = nonFatalLedger.chain.filter(b => b.event.type === 'PIPELINE_STEP_FAILED');
  assert.strictEqual(failedAudit.length, 1);
  assert.strictEqual(failedAudit[0].event.nodeId, 'step_err');

  // 11. Step Error Policy: fallback value & $steps syntax
  const fallbackLedger = new AuditLedger();
  const fallbackEngine = new DAGEngine({ ledger: fallbackLedger });
  const fallbackPipeline = {
    id: 'fallback-pipeline',
    nodes: [
      {
        id: 'fetch_remote_conf',
        server: 'mock',
        tool: 'fetch',
        params: {},
        fallback: { host: '127.0.0.1', port: 8080 }
      },
      {
        id: 'apply_conf',
        server: 'mock',
        tool: 'apply',
        params: {
          targetHost: '$steps.fetch_remote_conf.result.host',
          targetPort: '$steps.fetch_remote_conf.result.port'
        }
      }
    ]
  };
  let appliedParams = null;
  const fallbackInvoker = async (server, tool, params) => {
    if (tool === 'fetch') {
      return { isError: true, content: [{ type: 'text', text: 'Network timeout fetching remote config' }] };
    }
    appliedParams = params;
    return { content: [{ type: 'text', text: JSON.stringify({ applied: true }) }] };
  };
  const fallbackRes = await fallbackEngine.executePipeline(fallbackPipeline, fallbackInvoker);
  assert.strictEqual(fallbackRes.status, 'COMPLETED');
  assert.strictEqual(fallbackRes.context.nodes.fetch_remote_conf.status, 'FALLBACK');
  assert.deepStrictEqual(fallbackRes.context.nodes.fetch_remote_conf.output, { host: '127.0.0.1', port: 8080 });
  assert.deepStrictEqual(appliedParams, { targetHost: '127.0.0.1', targetPort: 8080 });
  const fallbackAudit = fallbackLedger.chain.filter(b => b.event.type === 'PIPELINE_STEP_FALLBACK');
  assert.strictEqual(fallbackAudit.length, 1);
  assert.strictEqual(fallbackAudit[0].event.nodeId, 'fetch_remote_conf');

  console.log('✅ Visual DAG Pipeline Engine: All 11 test cases passed!');
}

module.exports = { runPipelineTests };

if (require.main === module) {
  runPipelineTests().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
