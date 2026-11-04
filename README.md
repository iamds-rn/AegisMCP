# 🛡️ AegisMCP

> **Zero-Trust Security Firewall, Resilience Fuzzer, and Visual Observability Cockpit for the Model Context Protocol (MCP)**

[![Protocol: MCP 2024-11-05](https://img.shields.io/badge/Protocol-MCP%202024--11--05-00f0ff.svg)](https://modelcontextprotocol.io)
[![Tests: 36 Passing](https://img.shields.io/badge/Tests-36%20Assertions%20Passing-00ff9d.svg)](tests/)
[![Security: Zero--Trust](https://img.shields.io/badge/Security-Zero--Trust%20Firewall-ff3366.svg)](docs/FIREWALL_RULES.md)
[![Audit: Merkle Hash Chain](https://img.shields.io/badge/Audit-SHA--256%20Merkle%20Ledger-9d4edd.svg)](docs/ARCHITECTURE.md)
[![Dependencies: 0 External](https://img.shields.io/badge/Dependencies-0%20External-blue.svg)](package.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

🌐 **Live Web Studio & Interactive Playground:**  
👉 **[https://iamds-rn.github.io/AegisMCP/](https://iamds-rn.github.io/AegisMCP/)**

---

## ⚡ The Problem: The AI Agent Security Gap

In modern agentic AI architectures, Large Language Models (LLMs) are granted autonomous execution rights over tools—such as file systems, shell commands, databases, cloud APIs, and web search.

However, **LLMs generate tool parameters probabilistically**. When an agent encounters untrusted data (untrusted code, malicious user prompts, scraped websites, compromised emails), it is vulnerable to **Indirect Prompt Injection**:
- An attacker tricks the AI agent into executing `read_file({ path: "../../../../etc/shadow" })`.
- An attacker coaxes the model into leaking cloud credentials via `fetch_url({ url: "http://169.254.169.254/latest/meta-data/" })`.
- Hallucinated shell commands lead to destructive unintended command execution.

**AegisMCP** solves this by establishing a **Zero-Trust Security Layer** directly in the MCP protocol transport. It intercepts every JSON-RPC 2.0 tool call, inspects payloads against deterministic security invariants, records immutable Merkle audit proofs, and provides an interactive visual studio to fuzz and orchestrate MCP tools.

---

## ✨ Key Pillars & Innovations

### 1. 🛡️ Zero-Trust Tool Firewall & Policy Engine
- **Path Traversal Guard (`SEC-001`)**: Intercepts `../`, null bytes (`\x00`), and OS root escapements (`/etc/passwd`, `~/.ssh/id_rsa`, `C:\Windows\System32`).
- **Command Injection Guard (`SEC-002`)**: Intercepts shell metacharacters (`;`, `&&`, `||`, `|`, `` `id` ``, `$(...)`) and reverse-shell redirects.
- **Credential & Secret Leakage Guard (`SEC-003`)**: Scans parameters and responses for AWS keys (`AKIA...`), GitHub PATs (`ghp_...`), OpenAI keys (`sk-...`), and private keys using **Shannon Entropy analysis**.
- **SSRF & Cloud Metadata Guard (`SEC-004`)**: Blocks access to loopback (`127.0.0.1`), internal subnets (`10.0.0.0/8`, `192.168.0.0/16`), and AWS/GCP metadata endpoints (`169.254.169.254`).
- **DoS / Blast Radius Guard (`SEC-005`)**: Enforces payload size, JSON nesting depth, and element count constraints.
- **Three Operational Modes**:
  - `ENFORCE`: Immediately drops violations with standard JSON-RPC error `-32001 (AEGIS_POLICY_VIOLATION)`.
  - `SANITIZE`: Automatically scrubs secrets and normalizes traversal sequences before forwarding.
  - `AUDIT_ONLY`: Allows traffic while emitting high-severity audit logs.

### 2. 🔐 Tamper-Evident SHA-256 Merkle Audit Ledger
- Every protocol handshake, tool call, error, and firewall interception is recorded as an immutable block in a cryptographic hash chain:
  $$H_i = \text{SHA-256}\left( i \parallel \text{timestamp} \parallel H_{i-1} \parallel \text{Event}_i \right)$$
- Any modification, deletion, or reordering of historical records breaks the hash pointer and is immediately flagged by `verify()`.
- Exportable as a cryptographically verifiable JSON Audit Proof package.

### 3. 🔬 Schema-Driven Protocol Fuzzer & Conformance Auditor
- Automatically ingests any tool's JSON Schema and generates 6 classes of adversarial inputs:
  1. `SCHEMA_CONFORMANCE`: Missing required fields, unexpected structures.
  2. `NULL_MUTATION`: Explicit null parameters.
  3. `TYPE_MUTATION`: Passing objects for strings, strings for numbers, arrays for booleans.
  4. `BOUNDARY_VALUES`: 32KB buffer stress strings, `Number.MAX_SAFE_INTEGER`, negative infinities.
  5. `SECURITY_INJECTION`: Traversal sequences, shell injections, SSRF probes, credential tokens.
  6. `UNICODE_CHAOS`: Null bytes, BiDi RTL overrides (`\u202E`), zero-width joiners, emoji cascades.
- Outputs an automated **Resilience Scorecard (Grade A+ to F)** and Markdown Audit Report.

### 4. ⚡ Visual Directed Acyclic Graph (DAG) Pipeline Engine
- Connect tools from multiple disparate MCP servers into visual automated workflows.
- Dynamic data interpolation using template expressions: `{{nodes.source_step.output.hash}}`.
- Topological sorting with Kahn's algorithm and circular dependency detection.
- Visual Canvas graph editor with glowing bezier connections and step-by-step node execution status.

### 5. 📦 Virtual In-Memory MCP Fleet (Zero-Install)
Ships with 4 fully sandboxed, in-memory MCP servers implemented in pure JavaScript:
- `virtual_filesystem`: POSIX sandbox (`read_file`, `write_file`, `list_files`, `delete_file`, `file_stat`).
- `virtual_memory`: Tagged associative state store (`set_key`, `get_key`, `search_keys`, `list_keys`, `delete_key`).
- `virtual_crypto`: Cryptographic engine (`hash_sha256`, `hmac_sign`, `generate_token`, `eval_entropy`).
- `virtual_http_simulator`: Outbound HTTP simulator with mock endpoints and SSRF tripwires.

### 6. 🎛️ Cyberpunk Web Studio & Audio Synthesizer
- Zero-build, responsive obsidian dark-mode interface.
- Synthesizes dynamic auditory feedback using the Web Audio API (success harmonic chimes, security alarm pulses, subtle tactile clicks).
- Live telemetry counters, threat radar bar charts, and real-time protocol event stream.

---

## 🚀 Quickstart

### Option A: Open the Web Studio in Your Browser
No installation or backend required! Everything runs client-side in Web Workers and memory:  
👉 **[https://iamds-rn.github.io/AegisMCP/](https://iamds-rn.github.io/AegisMCP/)**

### Option B: Run Locally via Node.js
```bash
# Clone the repository
git clone https://github.com/iamds-rn/AegisMCP.git
cd AegisMCP

# Run automated tests
npm test

# Launch the Web Studio & Gateway on http://localhost:3333
npm start
```

### Option C: Run as an MCP stdio Proxy
Add AegisMCP to your Claude Desktop, Cursor, or AI agent configuration (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "aegis-shield": {
      "command": "node",
      "args": [
        "/path/to/AegisMCP/bin/aegis-mcp.js",
        "--stdio",
        "--mode",
        "ENFORCE"
      ]
    }
  }
}
```

---

## 🛠️ Command-Line Interface (CLI)

```bash
$ aegis-mcp --help

USAGE:
  aegis-mcp [command] [options]

COMMANDS:
  --serve              Launch Web Studio & API Gateway (Default port: 3333)
  --stdio              Run MCP stdio proxy with active firewall protection
  --fuzz               Run automated protocol fuzzing audit on virtual tools
  --verify-ledger      Perform cryptographic integrity check on audit ledger
  --help, -h           Show help manual

OPTIONS:
  --port <num>         Port for HTTP server (default: 3333)
  --mode <mode>        Firewall mode: ENFORCE, AUDIT_ONLY, SANITIZE (default: ENFORCE)
  --tool <name>        Target tool name for fuzzing (default: read_file)
```

---

## 🧪 Comprehensive Automated Test Suite

AegisMCP is verified by a strict, zero-dependency automated test runner:

```bash
$ npm test

🛡️  ==============================================================
    AEGIS-MCP COMPREHENSIVE AUTOMATED TEST SUITE
==============================================================

🧪 Testing Firewall Rules & Engine...
✅ Firewall Rules & Engine: All 9 test cases passed!
🧪 Testing Cryptographic Audit Ledger...
  Testing adversarial tamper detection...
✅ Cryptographic Audit Ledger: All 7 test cases passed!
🧪 Testing Virtual MCP Servers...
✅ Virtual In-Memory MCP Servers: All 4 servers passed verification!
🧪 Testing Visual DAG Pipeline Engine...
✅ Visual DAG Pipeline Engine: All 5 test cases passed!
🧪 Testing Protocol Fuzzer & Conformance Auditor...
✅ Protocol Fuzzer: All 3 test cases passed!
🧪 Testing End-to-End Protocol & HTTP Gateway Server...
✅ End-to-End Protocol & Gateway: All 8 test cases passed!

🛡️  ==============================================================
    ALL TEST SUITES PASSED! (6/6)
    Total Duration: 0.02s
==============================================================
```

---

## 📁 Repository Structure

```
AegisMCP/
├── bin/
│   └── aegis-mcp.js          # CLI executable binary
├── src/
│   ├── index.js              # Main library entry point
│   ├── firewall/
│   │   ├── rules.js          # Built-in security rules (SEC-001 - SEC-005)
│   │   └── engine.js         # Firewall inspection & policy engine
│   ├── ledger/
│   │   └── auditLedger.js    # SHA-256 Merkle-linked audit ledger
│   ├── fuzzer/
│   │   └── fuzzer.js         # Schema-driven adversarial protocol fuzzer
│   ├── pipeline/
│   │   └── dagEngine.js      # Topological DAG execution orchestrator
│   ├── servers/
│   │   └── virtualHub.js     # Sandboxed in-memory MCP servers fleet
│   └── protocol/
│       ├── jsonrpc.js        # Strict JSON-RPC 2.0 & MCP protocol framing
│       └── proxy.js          # HTTP/SSE/stdio gateway server
├── web/
│   ├── index.html            # Single-Page Web Cockpit & Studio
│   ├── style.css             # Cyberpunk obsidian design system
│   └── app.js                # Browser-native reactive studio controller
├── tests/
│   ├── runner.js             # Master test suite runner
│   ├── test-firewall.js      # Firewall & entropy unit tests
│   ├── test-ledger.js        # Merkle tamper-detection tests
│   ├── test-fuzzer.js        # Fuzz test generation tests
│   ├── test-pipeline.js      # Topological DAG & cycle tests
│   ├── test-virtual-servers.js# Sandboxed servers unit tests
│   └── test-e2e.js           # End-to-end JSON-RPC & HTTP gateway tests
├── docs/
│   ├── ARCHITECTURE.md       # Deep architectural specifications
│   ├── FIREWALL_RULES.md     # Signature specifications & custom DSL
│   └── SPECIFICATION.md      # MCP protocol extension schema
├── .github/workflows/
│   └── deploy.yml            # CI test runner & GitHub Pages deployment
├── package.json
└── LICENSE
```

---

## 📜 Specification & Standards

- **Model Context Protocol (MCP)**: Complies with protocol version `2024-11-05`.
- **JSON-RPC 2.0**: Complies with RFC 7693 / JSON-RPC specification.
- **Cryptographic Hashing**: SHA-256 Merkle-linked blocks.
- **Zero External Dependencies**: Pure Node.js standard library (`node:crypto`, `node:http`, `node:readline`, `node:fs`).

---

## ⚖️ License

MIT License. Designed and built with pride by [iamds-rn](https://github.com/iamds-rn).
