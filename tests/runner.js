/**
 * AegisMCP Master Test Runner
 * Executes all 11 test suites and generates execution summary.
 */

'use strict';

const { runFirewallTests } = require('./test-firewall');
const { runNewRulesTests } = require('./test-new-rules');
const { runLedgerTests } = require('./test-ledger');
const { runForensicsTests } = require('./test-forensics');
const { runSynthesizerTests } = require('./test-synthesizer');
const { runVirtualServerTests } = require('./test-virtual-servers');
const { runExternalServerTests } = require('./test-external-server');
const { runConfigGeneratorTests } = require('./test-config-generator');
const { runPipelineTests } = require('./test-pipeline');
const { runFuzzerTests } = require('./test-fuzzer');
const { runExploitGeneratorTests } = require('./test-exploit-generator');
const { runJsonRpcTests } = require('./test-jsonrpc');
const { runProxyEndpointsTests } = require('./test-proxy-endpoints');
const { runWebStudioTests } = require('./test-web-studio');
const { runE2ETests } = require('./test-e2e');
const { runMilestone2Tests } = require('./test-milestone2');
const { runLedgerPersistenceTests } = require('./test-ledger-persistence');
const { runEdgeCaseAuditTests } = require('./test-audit-edge-cases');
const { runProcessSupervisionTests } = require('./test-process-supervision');
const { runCliTests } = require('./test-cli');

async function main() {
  console.log(`
🛡️  ==============================================================
    AEGIS-MCP COMPREHENSIVE AUTOMATED TEST SUITE (v1.5.0)
==============================================================
`);

  const startTime = Date.now();
  let passedSuites = 0;
  const suites = [
    { name: 'Firewall Rules & Engine (SEC-001 to SEC-005)', fn: runFirewallTests },
    { name: 'Advanced Security Rules (SEC-006 to SEC-009)', fn: runNewRulesTests },
    { name: 'Cryptographic Audit Ledger', fn: runLedgerTests },
    { name: 'Time-Travel Forensics & Tamper Localization', fn: runForensicsTests },
    { name: 'Dynamic Security Rule Synthesizer', fn: runSynthesizerTests },
    { name: 'Automated Exploit Payload Generator & Resilience Auditor', fn: runExploitGeneratorTests },
    { name: 'Virtual MCP Servers Fleet', fn: runVirtualServerTests },
    { name: 'External MCP Server stdio Proxy Tunneling', fn: runExternalServerTests },
    { name: 'AI Client Configuration Generator', fn: runConfigGeneratorTests },
    { name: 'Visual DAG Pipeline Engine', fn: runPipelineTests },
    { name: 'Protocol Fuzzer & Conformance Auditor', fn: runFuzzerTests },
    { name: 'RFC 7693 & JSON-RPC 2.0 Protocol Engine', fn: runJsonRpcTests },
    { name: 'MCP Proxy Gateway & Endpoints Conformance', fn: runProxyEndpointsTests },
    { name: 'Web Studio UI/UX & Client Architecture', fn: runWebStudioTests },
    { name: 'End-to-End JSON-RPC & HTTP Gateway Server', fn: runE2ETests },
    { name: 'Milestone 2 Rate Limiter (-32003) & Execution Timeout (-32005)', fn: runMilestone2Tests },
    { name: 'Milestone 3 Ledger File Persistence & HMAC-SHA256 Attestation', fn: runLedgerPersistenceTests },
    { name: 'Deep Code Audit Edge Cases & Defect Reproductions', fn: runEdgeCaseAuditTests },
    { name: 'Milestone 4 Process Supervision, Concurrent DAG & Health Probes', fn: runProcessSupervisionTests },
    { name: 'Milestone 4 CLI Automation & Command-Line Interface', fn: runCliTests }
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
      ✔ Path Traversal Interception & Double Encoding (SEC-001)
      ✔ Command Injection Prevention & Recon Sanitization (SEC-002)
      ✔ Secret, Key & JWT Leakage Shield (SEC-003)
      ✔ SSRF & IPv4-Mapped IPv6 Cloud Metadata Protection (SEC-004)
      ✔ Payload Blast Radius / Recursive DoS Guard (SEC-005)
      ✔ Prompt Injection & Instruction Hijacking Guard (SEC-006)
      ✔ SQL, DML & Blind Sleep Injection Guard (SEC-007)
      ✔ Structured Prototype Pollution & Object Injection Guard (SEC-008)
      ✔ Cross-Platform Secrets & Environment Exfiltration Guard (SEC-009)
      ✔ Dynamic Security Rule Synthesis & Auto-Remediation
      ✔ Automated Weaponized Exploit Generation & Immune Auto-Defense
      ✔ Time-Travel Forensic Localization & Blast Radius Audit
      ✔ 1-Click Cryptographic Healing & Chain Restoration
      ✔ External MCP Server stdio Proxy Tunneling (Quoted Shell Handling)
      ✔ Drop-in Client Configs (Claude Desktop, Cursor, Zed, Windsurf)
      ✔ SHA-256 Merkle-Chained Tamper Detection
      ✔ Automated Schema Mutation & Protocol Fuzzing
      ✔ Multi-Server DAG Pipeline Orchestration
      ✔ Zero-Install In-Memory Server Sandboxing
      ✔ RFC 7693 / JSON-RPC 2.0 / MCP 2024-11-05 Conformance
      ✔ Sliding-Window Token Bucket Rate Limiter (-32003 AEGIS_RATE_LIMIT_EXCEEDED)
      ✔ Deterministic Execution Timeout Mapping (-32005 AEGIS_TIMEOUT)
      ✔ Append-Only Streaming JSONL Ledger Persistence & Crash Recovery
      ✔ HMAC-SHA256 Cryptographic Attestation Signatures & In-Chain Checkpoints
      ✔ Deep Code Audit Invariants: Null-Safety, Error Codes & Unhandled Rejection Immunity
      ✔ External Process Crash-Backoff Supervision & Exponential Recovery
      ✔ Liveness Health Checking & Periodic Heartbeat Probes
      ✔ Topological Tier Concurrency & Parallel Execution (Promise.all)
      ✔ Per-Tier Wall-Clock Durations & Cryptographic Ledger Hashing
      ✔ End-to-End CLI Automation: Subprocess Orchestration, Exit Codes & DAG Flags
==============================================================
`);
}

main().catch(err => {
  console.error('Fatal Runner Error:', err);
  process.exit(1);
});
