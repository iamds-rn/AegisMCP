/**
 * Tests for AegisMCP Protocol Fuzzer & Conformance Auditor
 */

'use strict';

const assert = require('node:assert');
const { ProtocolFuzzer } = require('../src/fuzzer/fuzzer');
const { FirewallEngine } = require('../src/firewall/engine');
const { VirtualFilesystemServer } = require('../src/servers/virtualHub');

async function runFuzzerTests() {
  console.log('🧪 Testing Protocol Fuzzer & Conformance Auditor...');

  const fuzzer = new ProtocolFuzzer();
  const fsServer = new VirtualFilesystemServer();
  const readFileTool = fsServer.getTools().find(t => t.name === 'read_file');

  // 1. Test case generation
  const testCases = fuzzer.generateTestCases(readFileTool);
  assert(testCases.length >= 10, `Expected at least 10 adversarial test cases, got ${testCases.length}`);

  const categories = new Set(testCases.map(tc => tc.category));
  assert(categories.has('SCHEMA_CONFORMANCE'), 'Must include SCHEMA_CONFORMANCE category');
  assert(categories.has('NULL_MUTATION'), 'Must include NULL_MUTATION category');
  assert(categories.has('TYPE_MUTATION'), 'Must include TYPE_MUTATION category');
  assert(categories.has('BOUNDARY_VALUES'), 'Must include BOUNDARY_VALUES category');
  assert(categories.has('SECURITY_INJECTION'), 'Must include SECURITY_INJECTION category');
  assert(categories.has('UNICODE_CHAOS'), 'Must include UNICODE_CHAOS category');

  // 2. Audit execution with firewall attached
  const firewall = new FirewallEngine();
  const invoker = (name, p) => fsServer.callTool(name, p);

  const audit = await fuzzer.runAudit(readFileTool, invoker, firewall);

  assert.strictEqual(audit.toolName, 'read_file');
  assert(audit.totalTests > 0);
  assert(audit.blockedCount > 0, 'Firewall should intercept malicious injection test cases');
  assert(audit.scorePct >= 70, `Resilience score should be >= 70%, got ${audit.scorePct}%`);
  assert(['A+', 'A', 'B'].includes(audit.grade), `Expected high resilience grade, got ${audit.grade}`);

  // 3. Markdown report generation
  const markdown = fuzzer.generateMarkdownReport(audit);
  assert(markdown.includes('# AegisMCP Security & Resilience Audit Report'), 'Report must contain header');
  assert(markdown.includes('Breakdown by Test Vector'), 'Report must contain breakdown table');
  assert(markdown.includes(audit.grade), 'Report must contain overall grade');

  // 4. Defensive generation against null/empty schemas
  assert.deepStrictEqual(fuzzer.generateTestCases(null), []);
  assert.deepStrictEqual(fuzzer.generateTestCases({}), []);
  assert.deepStrictEqual(fuzzer.generateTestCases({ inputSchema: null }), []);

  // 5. Nested object schema fuzzing
  const nestedTool = {
    name: 'nested_exec',
    inputSchema: {
      type: 'object',
      properties: {
        config: {
          type: 'object',
          properties: {
            filePath: { type: 'string' }
          }
        }
      }
    }
  };
  const nestedCases = fuzzer.generateTestCases(nestedTool);
  assert(nestedCases.length > 0, 'Should generate test cases for nested schemas');
  assert(nestedCases.some(tc => tc.name.includes('filePath')), 'Should generate test vector for nested property filePath');

  console.log('✅ Protocol Fuzzer: All 5 test cases passed!');
}

module.exports = { runFuzzerTests };

if (require.main === module) {
  runFuzzerTests().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
