/**
 * AegisMCP Master Test Runner
 * Executes all test suites and generates execution summary.
 */

'use strict';

const { runFirewallTests } = require('./test-firewall');
const { runLedgerTests } = require('./test-ledger');
const { runFuzzerTests } = require('./test-fuzzer');
const { runPipelineTests } = require('./test-pipeline');
const { runVirtualServerTests } = require('./test-virtual-servers');
const { runE2ETests } = require('./test-e2e');

async function main() {
  console.log(`
🛡️  ==============================================================
    AEGIS-MCP COMPREHENSIVE AUTOMATED TEST SUITE
==============================================================
`);

  const startTime = Date.now();
  let passedSuites = 0;
  const suites = [
    { name: 'Firewall Rules & Engine', fn: runFirewallTests },
    { name: 'Cryptographic Audit Ledger', fn: runLedgerTests },
    { name: 'Virtual MCP Servers', fn: runVirtualServerTests },
    { name: 'Visual DAG Pipeline Engine', fn: runPipelineTests },
    { name: 'Protocol Fuzzer & Auditor', fn: runFuzzerTests },
    { name: 'End-to-End JSON-RPC & Gateway', fn: runE2ETests }
  ];

  for (const suite of suites) {
    try {
      await suite.fn();
      passedSuites++;
    } catch (err) {
      console.error(`❌ Suite Failed: ${suite.name}`);
      console.error(err);
      process.exit(1);
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log(`
🛡️  ==============================================================
    ALL TEST SUITES PASSED! (${passedSuites}/${suites.length})
    Total Duration: ${duration}s
    Security Invariants Verified:
      ✔ Path Traversal Interception (SEC-001)
      ✔ Command Injection Prevention (SEC-002)
      ✔ Secret & Credential Leakage Shield (SEC-003)
      ✔ SSRF & Cloud Metadata Protection (SEC-004)
      ✔ Payload Blast Radius / DoS Guard (SEC-005)
      ✔ SHA-256 Merkle-Chained Tamper Detection
      ✔ Automated Schema Mutation & Protocol Fuzzing
      ✔ Multi-Server DAG Pipeline Orchestration
      ✔ Zero-Install In-Memory Server Sandboxing
      ✔ RFC 7693 / JSON-RPC 2.0 / MCP 2024-11-05 Conformance
==============================================================
`);
}

main().catch(err => {
  console.error('Fatal Runner Error:', err);
  process.exit(1);
});
