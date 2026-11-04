/**
 * AegisMCP - Main Entry Point
 * Exports all modules: Protocol, Firewall, Ledger, Fuzzer, Pipeline, Servers, and Proxy.
 */

'use strict';

const jsonrpc = require('./protocol/jsonrpc');
const rules = require('./firewall/rules');
const { FirewallEngine, MODES } = require('./firewall/engine');
const { AuditBlock, AuditLedger, sha256, GENESIS_PREV_HASH } = require('./ledger/auditLedger');
const { AuditFilePersistence, FilePersistence, LedgerPersistenceError } = require('./ledger/filePersistence');
const {
  attestBlock,
  verifyAttestation,
  recordAttestationCheckpoint,
  createAttestationCheckpoint,
  verifyAttestationCheckpoint,
  verifyAllAttestations,
  LedgerAttestor,
  ATTESTATION_EVENT_TYPE
} = require('./ledger/attestation');
const { ProtocolFuzzer } = require('./fuzzer/fuzzer');
const { DAGEngine } = require('./pipeline/dagEngine');
const {
  VirtualHub,
  VirtualFilesystemServer,
  VirtualMemoryServer,
  VirtualCryptoServer,
  VirtualHttpSimulatorServer
} = require('./servers/virtualHub');
const { DynamicRuleSynthesizer } = require('./firewall/synthesizer');
const { ExploitPayloadGenerator } = require('./firewall/exploitGenerator');
const { SemanticGuard } = require('./firewall/semanticGuard');
const { OutputScrubber, isValidLuhn, REDACTION_PATTERNS } = require('./firewall/outputScrubber');
const { AdaptiveImmuneLoop, MUTATION_STRATEGIES } = require('./firewall/adaptiveImmuneLoop');
const { AccessControlEngine, ApprovalGate } = require('./security/accessControl');
const { MtlsServer, MtlsClient, TEST_CERTS } = require('./transport/mtlsMesh');
const { MerkleTree, hashLeaf, hashNodes } = require('./ledger/merkleTree');
const { WasmSandbox, IsolatedVmSandbox, SandboxManager, SAMPLE_WASM_BINARY } = require('./sandbox/wasmSandbox');
const { TelemetryEngine, Span, parseTraceparent, formatTraceparent } = require('./observability/telemetry');
const { PrometheusExporter } = require('./observability/prometheusExporter');
const { ExternalProcessServer } = require('./servers/externalProcessServer');
const { ClientConfigGenerator } = require('./protocol/configGenerator');
const { AegisProxyServer } = require('./protocol/proxy');

module.exports = {
  // Protocol
  jsonrpc,
  ClientConfigGenerator,
  // Firewall & Semantic Defense
  FirewallEngine,
  MODES,
  rules,
  DynamicRuleSynthesizer,
  ExploitPayloadGenerator,
  SemanticGuard,
  OutputScrubber,
  isValidLuhn,
  REDACTION_PATTERNS,
  AdaptiveImmuneLoop,
  MUTATION_STRATEGIES,
  // Security & Access Control
  AccessControlEngine,
  ApprovalGate,
  // Transport & mTLS Mesh
  MtlsServer,
  MtlsClient,
  TEST_CERTS,
  // Audit Ledger, Persistence & Merkle Proofs
  AuditBlock,
  AuditLedger,
  sha256,
  GENESIS_PREV_HASH,
  AuditFilePersistence,
  FilePersistence,
  LedgerPersistenceError,
  MerkleTree,
  hashLeaf,
  hashNodes,
  // Cryptographic Attestation
  attestBlock,
  verifyAttestation,
  recordAttestationCheckpoint,
  createAttestationCheckpoint,
  verifyAttestationCheckpoint,
  verifyAllAttestations,
  LedgerAttestor,
  ATTESTATION_EVENT_TYPE,
  // Sandboxing
  WasmSandbox,
  IsolatedVmSandbox,
  SandboxManager,
  SAMPLE_WASM_BINARY,
  // Observability & Telemetry
  TelemetryEngine,
  Span,
  parseTraceparent,
  formatTraceparent,
  PrometheusExporter,
  // Fuzzer
  ProtocolFuzzer,
  // DAG Orchestration
  DAGEngine,
  // Virtual Servers Hub
  VirtualHub,
  VirtualFilesystemServer,
  VirtualMemoryServer,
  VirtualCryptoServer,
  VirtualHttpSimulatorServer,
  ExternalProcessServer,
  // Proxy Gateway
  AegisProxyServer
};
