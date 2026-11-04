# AegisMCP Architecture Guide

AegisMCP is a zero-trust security firewall, resilience fuzzer, and visual observability cockpit built for the **Model Context Protocol (MCP)** (specification `2024-11-05`).

```
                    ┌────────────────────────┐
                    │    AI Agent / Client   │
                    │  (Claude, Gemini, etc) │
                    └───────────┬────────────┘
                                │ JSON-RPC 2.0 (stdio / SSE / HTTP)
                                ▼
               ╔═════════════════════════════════════╗
               ║              AegisMCP               ║
               ║  ┌───────────────────────────────┐  ║
               ║  │     JSON-RPC 2.0 Parser       │  ║
               ║  └───────────────┬───────────────┘  ║
               ║                  │                  ║
               ║  ┌───────────────▼───────────────┐  ║
               ║  │   Zero-Trust Firewall Engine  │  ║
               ║  │  (SEC-001 ... SEC-005, Rules) │  ║
               ║  └───────────────┬───────────────┘  ║
               ║                  │                  ║
               ║  ┌───────────────▼───────────────┐  ║
               ║  │  SHA-256 Merkle Audit Ledger  │  ║
               ║  └───────────────┬───────────────┘  ║
               ║                  │                  ║
               ║  ┌───────────────▼───────────────┐  ║
               ║  │      Visual DAG Dispatcher    │  ║
               ║  └───────────────┬───────────────┘  ║
               ╚══════════════════╪══════════════════╝
                                  │ Forwarded Tool Calls
            ┌─────────────────────┼─────────────────────┐
            ▼                     ▼                     ▼
┌───────────────────────┐ ┌───────────────┐ ┌─────────────────────────┐
│  In-Memory Filesystem │ │  Memory & KV  │ │  External MCP Server    │
│  (Sandbox POSIX tree) │ │  Store & Tags │ │  (stdio / SSE / Docker) │
└───────────────────────┘ └───────────────┘ └─────────────────────────┘
```

---

## 1. Zero-Trust Tool Firewall

Unlike conventional software where API calls originate from deterministic code, AI agents generate tool parameters probabilistically based on language model generation. This introduces novel attack vectors:
- **Indirect Prompt Injection**: Malicious instructions embedded in untrusted external content (e.g. web pages, emails) instruct the model to execute dangerous tool calls.
- **Data Exfiltration**: The model is coaxed into passing sensitive API credentials or system files into network or logging tools.
- **Accidental Boundary Escapes**: Hallucinated parameters containing relative paths or shell operators.

AegisMCP introduces a real-time inspection proxy that evaluates every `tools/call` request before it reaches the target server:

### Firewall Policy Modes
1. **`ENFORCE`**: Violations are immediately quarantined. The call is aborted, and a JSON-RPC error `-32001 (AEGIS_POLICY_VIOLATION)` is returned with complete threat telemetry and recommendations.
2. **`SANITIZE`**: Parameter structures are rewritten in-flight: API keys and private certificates are scrubbed with `[REDACTED]`, and directory traversal prefixes (`../`) are neutralized before passing downstream.
3. **`AUDIT_ONLY`**: Payloads pass unmodified, but alerts are dispatched to the cryptographic audit ledger for post-incident forensics.

---

## 2. Cryptographic Tamper-Evident Audit Ledger

To prevent attackers or compromised sub-agents from altering historical tool invocation logs, AegisMCP records every protocol transaction into a **Merkle-linked SHA-256 hash chain**:

$$H_i = \text{SHA-256}\left( i \parallel \text{timestamp} \parallel H_{i-1} \parallel \text{CanonicalJSON}(\text{Event}_i) \right)$$

- **Genesis Block**: Root block with index `0` and a null previous hash (`00...00`).
- **Strict Verification (`verify()`)**: Sequentially recomputes hashes from Genesis to Head. Any modification, re-ordering, or deletion of past entries causes an immediate pointer mismatch, pinpointing the exact corrupted block index.
- **Cryptographic Proof Export**: Exports verifiable JSON proofs with block heights, head hash, and event summaries.

---

## 3. Protocol Fuzzer & Conformance Auditor

Building robust MCP servers requires testing against erratic or adversarial inputs. AegisMCP includes an automated schema-aware fuzzer that parses JSON Schema definitions and generates 6 attack categories:
1. **`SCHEMA_CONFORMANCE`**: Missing mandatory fields, unexpected extra keys.
2. **`NULL_MUTATION`**: Explicit nulls, type coercions.
3. **`TYPE_MUTATION`**: Passing objects where strings expected, strings where integers expected.
4. **`BOUNDARY_VALUES`**: 32KB buffer stress strings, `Number.MAX_SAFE_INTEGER`, negative infinities.
5. **`SECURITY_INJECTION`**: Path traversal, command chaining, subshell execution, AWS/GitHub credential leakage, and SSRF loopback probes.
6. **`UNICODE_CHAOS`**: Null byte injections (`\x00`), BiDi RTL overrides, zero-width non-joiners, astral emoji bursts.

The fuzzer evaluates whether the server handles these gracefully without unhandled crashes, socket drops, or silent execution of malicious payloads, producing a letter-graded **Resilience Scorecard (A+ to F)**.

---

## 4. Visual Directed Acyclic Graph (DAG) Engine

AegisMCP enables chaining tools across multiple servers into deterministic execution DAGs:
- **Topological Sorting**: Uses Kahn's algorithm to analyze parameter dependencies (`{{nodes.source.output.field}}`) and execute nodes in valid causal order.
- **Cycle Detection**: Identifies circular references and halts execution before runtime deadlocks occur.
- **In-Flight Firewall Gate**: Every intermediate step in the pipeline is independently validated against security policies before dispatch.

---

## 5. Live External MCP Server stdio Proxy Tunneling

AegisMCP functions as an upstream zero-trust proxy for real-world external MCP server processes:
- **Child Process Supervision**: Spawns and manages external MCP server processes over `stdio` (`child_process.spawn`).
- **Autonomous Protocol Handshake**: Executes JSON-RPC 2.0 protocol negotiation (`initialize` and notifications `notifications/initialized`).
- **Dynamic Tool Federation**: Queries upstream `tools/list` and namespaces external tools alongside local virtual tools.
- **Bi-Directional Inspection**: Inbound requests from the AI client and outbound tool responses from the server are passed through the zero-trust firewall and Merkle audit ledger before delivery.
- **Fail-Safe Process Management**: Tracks health pings, request timeouts, and clean SIGTERM/SIGKILL lifecycle termination.

---

## 6. Time-Travel Ledger Forensics & Tamper Localization

AegisMCP provides advanced cryptographic forensics capabilities:
- **Tamper Pinpointing (`locateTamper()`)**: Recursively audits the SHA-256 Merkle chain to identify the exact block index where tampering occurred.
- **Blast Radius & Cascade Impact**: Computes total affected downstream blocks, unverified audit window duration, and lists affected tool names.
- **Deep Property Diffing**: Identifies modified keys, previous hash violations, and corrupted event data.
- **Time-Travel Snapshots (`getSnapshotAtBlock(index)`)**: Reconstructs the exact historical state of the system up to any block height without replaying entire logs.
- **1-Click Cryptographic Healing (`restoreChain(index)`)**: Recalculates cryptographic hash pointers from a clean state or removes invalid blocks to re-establish integrity.

---

## 7. Dynamic Security Rule Synthesizer

- Analyzes tool JSON schemas dynamically to generate zero-trust validation constraints.
- Hot-reloads threat signatures into the live proxy pipeline with zero downtime.
- Emits real-time telemetry into the Web Studio threat matrix.

---

## 8. AI Client Configuration Generator

Outputs ready-to-paste configurations tailored for leading AI development environments:
- **Claude Desktop**: Native `claude_desktop_config.json` with stdio process commands.
- **Cursor**: `.cursor/mcp.json` structure for editor integration.
- **Zed**: `settings.json` context server block.
- **Windsurf**: `mcp_config.json` schema.
- **HTTP/SSE Gateway**: Direct curl / web-ready endpoint definitions.

---

## 9. Automated Exploit Payload Generator & Self-Healing Immune Cycle (v1.2.0)

AegisMCP features an active adversarial auditing engine that goes beyond passive validation to generate weaponized exploits against tool definitions:
- **Weaponized Threat Vectors**: Generates realistic payloads targeting 9 distinct attack surfaces:
  1. `PATH_TRAVERSAL`: POSIX `../../`, double-URL encoded `%252e%252e%252f`, null-byte poisoning `\x00`, Windows backslashes `..\..\`.
  2. `COMMAND_INJECTION`: Subshells, semicolon chaining, pipe redirectors, newlines, and recon binaries (`whoami`, `id`, `uname`, `env`).
  3. `SECRET_LEAKAGE`: AWS access keys, GitHub PATs, OpenAI keys, Stripe live keys, Google API keys, and JWT signatures.
  4. `SSRF_EGRESS`: IPv4-mapped IPv6 loopbacks (`[::ffff:127.0.0.1]`), cloud metadata IP variants (`[::ffff:169.254.169.254]`), and non-HTTP protocols (`file://`, `gopher://`).
  5. `PROMPT_INJECTION`: Direct jailbreaks, roleplay subversions, model delimiters (`<<SYS>>`, `<start_of_turn>`, `[INST]`), and bidirectional Unicode evasion.
  6. `SQL_INJECTION`: Destructive DML (`DELETE`, `DROP`), boolean tautologies (`' OR '1'='1`), and blind time-delay sleep calls (`pg_sleep`, `WAITFOR DELAY`).
  7. `PROTOTYPE_POLLUTION`: Structured object injection (`{ constructor: { prototype: ... } }`) and own-property `__proto__` injection.
  8. `ENV_SECRETS_EXFILTRATION`: Targeting `.env.production`, `.aws/credentials`, Kubernetes client config, and SSH private keys.
  9. `DOS_BUFFER_EXHAUSTION`: Recursive nesting depth stress (>12 levels) and oversized buffer exhaustion (>512 KB).
- **Self-Healing Closed Loop**:
  When an exploit penetrates the baseline defenses in audit mode, Aegis triggers `DynamicRuleSynthesizer.synthesizeRulesForTool()`, instantly synthesizing and hot-reloading a specific countermeasure rule into the live firewall engine with zero server restarts.
- **Exploit Studio UI**:
  Visual penetration testing console in the Web Studio with 1-click execution, categorized threat badges, defensive mechanism trace, and automatic immune defense activation.


