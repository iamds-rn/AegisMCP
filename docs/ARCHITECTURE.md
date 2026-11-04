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
