# AegisMCP Protocol & Extension Specification
**Version:** 1.0.0  
**Base Protocol:** Model Context Protocol (MCP) Version `2024-11-05`  
**Wire Transport:** JSON-RPC 2.0 (RFC 7693) over stdio / SSE / HTTP  

---

## 1. Abstract
This document formally specifies the protocol extensions, JSON-RPC error codes, security capability flags, and cryptographic audit schema introduced by **AegisMCP**.

---

## 2. Capabilities Negotiation

During protocol handshake (`initialize`), AegisMCP advertises its security capabilities under `capabilities.aegis`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": { "listChanged": true },
      "resources": {},
      "prompts": {},
      "aegis": {
        "firewall": true,
        "auditLedger": true,
        "fuzzer": true,
        "version": "1.0.0"
      }
    },
    "serverInfo": {
      "name": "AegisMCP-Proxy",
      "version": "1.0.0"
    }
  }
}
```

---

## 3. JSON-RPC Error Codes

AegisMCP reserves the `-32001` through `-32010` block for security policy enforcement:

| Code | Constant | Meaning |
| :--- | :--- | :--- |
| `-32001` | `AEGIS_POLICY_VIOLATION` | Inbound tool call triggered an active security rule. |
| `-32002` | `AEGIS_QUARANTINE_TRIGGERED`| Malicious behavior identified; execution quarantined. |
| `-32003` | `AEGIS_RATE_LIMIT_EXCEEDED` | Tool call volume exceeded threshold. |
| `-32004` | `AEGIS_PAYLOAD_TOO_LARGE`   | Argument size exceeds blast radius constraints. |
| `-32005` | `AEGIS_TIMEOUT`             | Tool execution timed out. |

### Error Response Schema (`-32001`)

```json
{
  "jsonrpc": "2.0",
  "id": "req-142",
  "error": {
    "code": -32001,
    "message": "AegisMCP Security Firewall Block: [SEC-001] Path Traversal Guard triggered.",
    "data": {
      "ruleId": "SEC-001",
      "ruleName": "Path Traversal Guard",
      "severity": "CRITICAL",
      "signature": "Directory Traversal Sequence (..)",
      "culprit": "../../../../etc/passwd",
      "recommendation": "Modify tool arguments to comply with security policy."
    }
  }
}
```

---

## 4. Cryptographic Proof Schema

The tamper-evident audit proof is exported via `GET /api/ledger/proof` or `exportProof()`:

```json
{
  "proofVersion": "1.0",
  "timestamp": "2026-11-04T01:25:00.000Z",
  "integrityStatus": "VERIFIED_PRISTINE",
  "blockCount": 42,
  "headHash": "ba9e9a7c80b7d69cea47b6f8c41cbf2f6a8a2c74331d6c0c16c7ca4b8828e848",
  "genesisHash": "d9108a125282a03ccce9ddd66fcd16f4f95d1f41e03b523463a0253bbb2fe1dd",
  "blocks": [
    {
      "index": 0,
      "timestamp": "2026-11-04T00:00:00.000Z",
      "prevHash": "0000000000000000000000000000000000000000000000000000000000000000",
      "hash": "d9108a125282a03ccce9ddd66fcd16f4f95d1f41e03b523463a0253bbb2fe1dd",
      "eventType": "GENESIS",
      "eventSummary": "AegisMCP Cryptographic Audit Ledger Initialized"
    }
  ]
}
```
