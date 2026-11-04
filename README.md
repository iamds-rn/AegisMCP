# 🛡️ AegisMCP

> **Zero-Trust Security Firewall, Resilience Fuzzer, External Stdio Tunnel, and Visual Observability Cockpit for the Model Context Protocol (MCP)**

[![Protocol: MCP 2024-11-05](https://img.shields.io/badge/Protocol-MCP%202024--11--05-00f0ff.svg)](https://modelcontextprotocol.io)
[![Tests: All Passing](https://img.shields.io/badge/Tests-73%20Assertions%20Passing-00ff9d.svg)](tests/)
[![Security: Zero--Trust](https://img.shields.io/badge/Security-Zero--Trust%20Firewall%20(SEC--001..009)-ff3366.svg)](docs/FIREWALL_RULES.md)
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
- Malicious SQL queries or prototype pollution payloads escape isolation boundaries.

**AegisMCP** solves this by establishing a **Zero-Trust Security Layer** directly in the MCP protocol transport. It intercepts every JSON-RPC 2.0 tool call, inspects payloads against deterministic security invariants, records immutable Merkle audit proofs, tunnels traffic to external MCP processes, and provides an interactive visual studio to fuzz, orchestrate, and audit MCP tools.

---

## ✨ Key Pillars & Innovations (v1.1.0)

### 1. 🛡️ Zero-Trust Tool Firewall & Policy Engine (SEC-001 to SEC-009)
- **Path Traversal Guard (`SEC-001`)**: Intercepts `../`, null bytes (`\x00`), and OS root escapements (`/etc/passwd`, `~/.ssh/id_rsa`, `C:\Windows\System32`).
- **Command Injection Guard (`SEC-002`)**: Intercepts shell metacharacters (`;`, `&&`, `||`, `|`, `` `id` ``, `$(...)`) and reverse-shell redirects.
- **Credential & Secret Leakage Guard (`SEC-003`)**: Scans parameters and responses for AWS keys (`AKIA...`), GitHub PATs (`ghp_...`), OpenAI keys (`sk-...`), Anthropic keys (`sk-ant-...`), and private keys using **Shannon Entropy analysis**.
- **SSRF & Cloud Metadata Guard (`SEC-004`)**: Blocks access to loopback (`127.0.0.1`), internal subnets (`10.0.0.0/8`, `192.168.0.0/16`), and AWS/GCP metadata endpoints (`169.254.169.254`).
- **DoS / Blast Radius Guard (`SEC-005`)**: Enforces payload size, JSON nesting depth, and element count constraints.
- **Prompt Injection & Hijacking Guard (`SEC-006`)**: Blocks instruction overrides (`ignore previous instructions`), roleplay exploits (`DAN mode`), marker injections (`[INST]`, `<|im_start|>`), and hidden character bypasses (BiDi RTL, zero-width spaces).
- **SQL & Query Injection Guard (`SEC-007`)**: Blocks SQL tautology escapes (`' OR '1'='1`), stacked queries (`DROP TABLE`), comment truncations, and stored procedures (`xp_cmdshell`).
- **Prototype Pollution Guard (`SEC-008`)**: Intercepts `__proto__`, `constructor.prototype`, and prototype mutations on parameter objects.
- **Environment & Secrets Exfiltration Guard (`SEC-009`)**: Prevents reading `.env`, `.envrc`, AWS credentials, and shell histories.
- **Three Operational Modes**:
  - `ENFORCE`: Immediately drops violations with standard JSON-RPC error `-32001 (AEGIS_POLICY_VIOLATION)`.
  - `SANITIZE`: Automatically scrubs secrets, neutralizes traversal sequences, and strips prototype keys before forwarding.
  - `AUDIT_ONLY`: Allows traffic while emitting high-severity audit logs.

### 2. 🔌 Live External MCP Server stdio Proxy Tunneling
- Supervise and tunnel real-world external MCP server processes (`child_process.spawn`).
- Transparently proxies MCP protocol handshakes (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`).
- Automatically namespaces upstream tools alongside local sandboxed tools.
- Intercepts requests and responses in-flight through the firewall and Merkle audit ledger before reaching clients or servers.
- Full process lifecycle management with heartbeat monitoring, timeout defense, and graceful shutdown.

### 3. ⏳ Time-Travel Ledger Forensics & Tamper Localization
- **Tamper Localization (`locateTamper()`)**: Recursively audits the SHA-256 Merkle chain to pinpoint the exact corrupted block index.
- **Blast Radius & Cascade Analysis**: Quantifies downstream invalidation cascade, affected duration window, and compromised tool names.
- **Deep Property Diffing**: Identifies exactly which parameters or block headers were altered.
- **Time-Travel Snapshots (`getSnapshotAtBlock()`)**: Reconstructs the historical system state at any point in time.
- **1-Click Cryptographic Healing (`restoreChain()`)**: Re-hashes and heals or truncates corrupted blocks to restore chain integrity.

### 4. 🧬 Dynamic Security Rule Synthesizer & Hot-Reloading
- **Schema-Driven Rule Synthesis**: Inspects tool input schemas (detecting query, path, url, command fields) and generates tailored zero-trust rules on the fly.
- **Threat Signature Compiler**: Compiles custom regex signatures into active firewall rules with live telemetry and violation metrics.
- **Hot-Reloading**: Activates or toggles rules at runtime without server restarts.

### 5. 💻 Instant AI Client Configuration Generator
Generates drop-in, copy-paste ready MCP configuration blocks for:
- **Claude Desktop** (`claude_desktop_config.json`)
- **Cursor** (`.cursor/mcp.json`)
- **Zed** (`settings.json`)
- **Windsurf** (`mcp_config.json`)
- **HTTP / SSE Gateway** (Direct REST / cURL endpoints)

### 6. 🔬 Schema-Driven Protocol Fuzzer & Conformance Auditor
- Generates 6 adversarial test classes: `SCHEMA_CONFORMANCE`, `NULL_MUTATION`, `TYPE_MUTATION`, `BOUNDARY_VALUES`, `SECURITY_INJECTION`, and `UNICODE_CHAOS`.
- Outputs a letter-graded **Resilience Scorecard (Grade A+ to F)** and downloadable Markdown audit report.

### 7. ⚡ Visual Directed Acyclic Graph (DAG) Pipeline Engine
- Connect tools across multiple servers into visual automated workflows.
- Dynamic data interpolation using template expressions: `{{nodes.source_step.output.hash}}`.
- Topological sorting with Kahn's algorithm and circular dependency detection.

### 8. 📦 Virtual In-Memory MCP Fleet (Zero-Install)
- `virtual_filesystem`: POSIX sandbox (`read_file`, `write_file`, `list_files`, `delete_file`, `file_stat`).
- `virtual_memory`: Tagged associative state store (`set_key`, `get_key`, `search_keys`, `list_keys`, `delete_key`).
- `virtual_crypto`: Cryptographic engine (`hash_sha256`, `hmac_sign`, `generate_token`, `eval_entropy`).
- `virtual_http_simulator`: Outbound HTTP simulator with mock endpoints and SSRF tripwires.

### 9. 🎛️ Cyberpunk Web Studio & Cockpit
- Zero-build obsidian dark-mode interface with Web Audio synthesizer feedback.
- Interactive Time-Travel scrubber with live tamper injection & 1-click restore.
- Dynamic rule synthesizer editor and client config exporter.
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

# Run automated tests (73 assertions across 11 suites)
npm test

# Launch the Web Studio & Gateway on http://localhost:3333
npm start
```

### Option C: Run as an MCP Proxy for External Servers
Tunnel an existing external MCP server through AegisMCP's zero-trust firewall:
```bash
# Proxy an external server over stdio
aegis-mcp --proxy "npx -y @modelcontextprotocol/server-filesystem /tmp" --mode ENFORCE
```

### Option D: Drop-in AI Client Configuration
Generate configuration for your AI editor:
```bash
# Generate config for Claude Desktop, Cursor, Zed, or Windsurf
aegis-mcp --generate-config claude
aegis-mcp --generate-config cursor
```

Or paste directly into `claude_desktop_config.json`:
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
  --serve                      Launch Web Studio & API Gateway (Default port: 3333)
  --stdio                      Run MCP stdio proxy with active firewall protection
  --proxy <cmd>                Tunnel an external MCP server command through the firewall
  --fuzz                       Run automated protocol fuzzing audit on virtual tools
  --verify-ledger              Perform cryptographic integrity check on audit ledger
  --forensics                  Run time-travel forensics & tamper localization audit
  --generate-config <client>   Generate client config (claude|cursor|zed|windsurf|all)
  --synthesize <tool>          Synthesize zero-trust firewall rules for a tool schema
  --help, -h                   Show help manual

OPTIONS:
  --port <num>                 Port for HTTP server (default: 3333)
  --mode <mode>                Firewall mode: ENFORCE, AUDIT_ONLY, SANITIZE (default: ENFORCE)
  --tool <name>                Target tool name for fuzzing/synthesis (default: read_file)
```

---

## 🧪 Comprehensive Automated Test Suite

AegisMCP is verified by a strict, zero-dependency automated test runner:

```bash
$ npm test

🛡️  ==============================================================
    AEGIS-MCP COMPREHENSIVE AUTOMATED TEST SUITE (v1.1.0)
==============================================================

🧪 Testing Firewall Rules & Engine...
✅ Firewall Rules & Engine: All 11 test cases passed!
🧪 Testing Advanced Security Rules (SEC-006 to SEC-009)...
✅ Advanced Security Rules: All 6 test cases passed!
🧪 Testing Cryptographic Audit Ledger...
  Testing adversarial tamper detection...
✅ Cryptographic Audit Ledger: All 10 test cases passed!
🧪 Testing Time-Travel Ledger Forensics & Tamper Localization...
✅ Time-Travel Forensics & Tamper Localization: All 6 test cases passed!
🧪 Testing Dynamic Rule Synthesizer & Hot-Reloading...
✅ Dynamic Rule Synthesizer: All 6 test cases passed!
🧪 Testing Virtual MCP Servers...
  Testing server parameter validation invariants...
✅ Virtual In-Memory MCP Servers: All 4 servers passed verification!
🧪 Testing External MCP Server stdio Proxy Tunneling...
✅ External MCP Server stdio Proxy Tunneling: All 6 test cases passed!
🧪 Testing AI Client Configuration Generator...
✅ Client Configuration Generator: All 7 test cases passed!
🧪 Testing Visual DAG Pipeline Engine...
✅ Visual DAG Pipeline Engine: All 6 test cases passed!
🧪 Testing Protocol Fuzzer & Conformance Auditor...
✅ Protocol Fuzzer: All 5 test cases passed!
🧪 Testing End-to-End Protocol & HTTP Gateway Server...
✅ End-to-End Protocol & Gateway: All 10 test cases passed!

🛡️  ==============================================================
    ALL TEST SUITES PASSED! (11/11)
    Total Duration: 0.04s
==============================================================
```

---

## 📁 Repository Structure

```
AegisMCP/
├── bin/
│   └── aegis-mcp.js               # CLI executable binary with proxy/forensics/config commands
├── src/
│   ├── index.js                   # Main library entry point
│   ├── firewall/
│   │   ├── rules.js               # Built-in security rules (SEC-001 - SEC-009)
│   │   ├── engine.js              # Firewall inspection, sanitization & policy engine
│   │   └── synthesizer.js         # Dynamic schema-driven rule synthesizer
│   ├── ledger/
│   │   └── auditLedger.js         # SHA-256 Merkle ledger, forensics & time-travel snapshots
│   ├── fuzzer/
│   │   └── fuzzer.js              # Schema-driven adversarial protocol fuzzer
│   ├── pipeline/
│   │   └── dagEngine.js           # Topological DAG execution orchestrator
│   ├── servers/
│   │   ├── virtualHub.js          # Sandboxed in-memory & external server fleet hub
│   │   └── externalProcessServer.js # Child process stdio/SSE proxy adapter
│   └── protocol/
│       ├── jsonrpc.js             # Strict JSON-RPC 2.0 & MCP protocol framing
│       ├── proxy.js               # HTTP/SSE/stdio gateway & REST management API
│       └── configGenerator.js     # Claude/Cursor/Zed/Windsurf client config generator
├── web/
│   ├── index.html                 # Single-Page Web Cockpit & Forensics Studio
│   ├── style.css                  # Cyberpunk obsidian design system
│   └── app.js                     # Browser-native reactive studio & audio synthesizer
├── tests/
│   ├── runner.js                  # Master test suite runner (11 suites)
│   ├── test-firewall.js           # Core firewall & entropy unit tests
│   ├── test-new-rules.js          # Advanced rules (SEC-006 to SEC-009) tests
│   ├── test-ledger.js             # Merkle chain integrity tests
│   ├── test-forensics.js          # Tamper localization, blast radius & snapshot tests
│   ├── test-synthesizer.js        # Schema analysis & hot-reloading tests
│   ├── test-external-server.js    # Child process stdio tunneling tests
│   ├── mock-mcp-server.js         # Standalone external test process
│   ├── test-config-generator.js   # Client config formatting tests
│   ├── test-fuzzer.js             # Adversarial fuzz mutation tests
│   ├── test-pipeline.js           # DAG orchestration & interpolation tests
│   ├── test-virtual-servers.js    # Sandboxed in-memory servers tests
│   └── test-e2e.js                # End-to-end JSON-RPC & HTTP gateway tests
├── docs/
│   ├── ARCHITECTURE.md            # Deep architectural specifications & proxy model
│   ├── FIREWALL_RULES.md          # Signatures catalog & dynamic synthesis DSL
│   └── SPECIFICATION.md           # MCP protocol extension schema
├── .github/workflows/
│   └── deploy.yml                 # CI test runner & GitHub Pages deployment
├── package.json
└── LICENSE
```

---

## 📜 Specification & Standards

- **Model Context Protocol (MCP)**: Complies with protocol version `2024-11-05`.
- **JSON-RPC 2.0**: Complies with RFC 7693 / JSON-RPC specification.
- **Cryptographic Hashing**: SHA-256 Merkle-linked blocks with zero external dependencies.
- **Zero External Dependencies**: Pure Node.js standard library (`node:crypto`, `node:http`, `node:readline`, `node:fs`, `node:child_process`).

---

## ⚖️ License

MIT License. Designed and built with pride by [iamds-rn](https://github.com/iamds-rn).

