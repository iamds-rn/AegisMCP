/**
 * AegisMCP - Main Entry Point
 * Exports all modules: Protocol, Firewall, Ledger, Fuzzer, Pipeline, Servers, and Proxy.
 */

'use strict';

const jsonrpc = require('./protocol/jsonrpc');
const rules = require('./firewall/rules');
const { FirewallEngine, MODES } = require('./firewall/engine');
const { AuditBlock, AuditLedger, sha256 } = require('./ledger/auditLedger');
const { ProtocolFuzzer } = require('./fuzzer/fuzzer');
const { DAGEngine } = require('./pipeline/dagEngine');
const {
  VirtualHub,
  VirtualFilesystemServer,
  VirtualMemoryServer,
  VirtualCryptoServer,
  VirtualHttpSimulatorServer
} = require('./servers/virtualHub');
const { AegisProxyServer } = require('./protocol/proxy');

module.exports = {
  // Protocol
  jsonrpc,
  // Firewall
  FirewallEngine,
  MODES,
  rules,
  // Audit Ledger
  AuditBlock,
  AuditLedger,
  sha256,
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
  // Proxy Gateway
  AegisProxyServer
};
