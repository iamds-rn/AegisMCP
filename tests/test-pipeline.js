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

  // 1. Dependency extraction
  const sampleParams = {
    key: '{{nodes.step1.output.secret}}',
    nested: { ref: '{{nodes.step2.output.data.hash}}' },
    normal: 'literal_value'
  };
  const deps = extractDependencies(sampleParams);
  assert.deepStrictEqual(deps.sort(), ['step1', 'step2']);

  // 2. Value interpolation
  const context = {
    nodes: {
      step1: { output: { secret: 'alpha_key_99' } },
      step2: { output: { data: { hash: 'e3b0c442' } } }
    }
  };
  const interpolated = interpolateValue(sampleParams, context);
  assert.strictEqual(interpolated.key, 'alpha_key_99');
  assert.strictEqual(interpolated.nested.ref, 'e3b0c442');
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

  // 4. Cycle detection
  const cyclicNodes = [
    { id: 'cycle_1', params: { in: '{{nodes.cycle_2.output.x}}' } },
    { id: 'cycle_2', params: { in: '{{nodes.cycle_1.output.x}}' } }
  ];
  assert.throws(() => engine.resolveExecutionOrder(cyclicNodes), /Cyclic dependency detected/);

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

  console.log('✅ Visual DAG Pipeline Engine: All 5 test cases passed!');
}

module.exports = { runPipelineTests };

if (require.main === module) {
  runPipelineTests().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
