# AegisMCP Security Rules & Threat Signatures

This document catalogs the built-in threat detection rules implemented in the AegisMCP Zero-Trust Engine.

---

## Built-In Detection Rules

### SEC-001: Path Traversal Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block & Isolate
- **Target Fields**: Any string argument within `tools/call` parameters
- **Signatures Detected**:
  - `../`, `..\`, `%2e%2e%2f`, `%2e%2e/`, `..;/`
  - Sensitive UNIX paths: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/proc/self`, `/proc/[pid]`, `/sys/`, `/var/run/secrets`
  - User configuration and key directories: `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.bash_history`
  - Windows system roots: `C:\Windows\System32`, `\\.\`

### SEC-002: Command Injection Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block & Isolate
- **Target Fields**: Tool arguments, command parameters, subshell strings
- **Signatures Detected**:
  - Command chaining metacharacters: `;`, `&&`, `||`, `|`
  - Subshell operators: `` `command` ``, `$(command)`
  - Dangerous binaries chained unquoted: `rm`, `cat`, `curl`, `wget`, `bash`, `sh`, `nc`, `mkfifo`, `powershell`, `python`
  - Reverse shell redirection: `> /dev/tcp/`, `> /dev/udp/`
  - Dynamic evaluation calls: `eval(...)`, `exec(...)`

### SEC-003: Credential & Secret Leakage Guard
- **Severity**: `HIGH`
- **Default Action**: Block (ENFORCE) or Scrub (SANITIZE)
- **Target Fields**: Inbound parameters and outbound tool responses
- **Signatures Detected**:
  - **AWS Access Key ID**: `\bAKIA[0-9A-Z]{16}\b`
  - **GitHub PAT**: `\b(ghp_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{50,})\b`
  - **OpenAI API Key**: `\b(sk-[A-Za-z0-9]{32,}|sk-proj-[A-Za-z0-9_-]{40,})\b`
  - **Anthropic API Key**: `\b(sk-ant-[A-Za-z0-9_-]{30,})\b`
  - **Slack Token**: `\bxox[baprs]-[0-9A-Za-z]{10,}\b`
  - **Private Keys**: `-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? PRIVATE KEY-----`
  - **Shannon Entropy Scanner**: Strings between 32 and 128 characters with Shannon entropy $> 4.65$ bits/char.

### SEC-004: SSRF & Cloud Metadata Protection
- **Severity**: `HIGH`
- **Default Action**: Block & Isolate
- **Target Fields**: Destination URLs, endpoint URIs, webhook parameters
- **Signatures Detected**:
  - Loopback addresses: `localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`, `127.0.0.0/8`
  - Cloud instance metadata services: `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`
  - RFC 1918 Private Ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Dangerous URL protocols: `file://`, `gopher://`, `dict://`, `tftp://`, `sftp://`

### SEC-005: Payload Blast Radius & DoS Guard
- **Severity**: `MEDIUM`
- **Default Action**: Block
- **Thresholds**:
  - Maximum JSON payload size: `512 KB`
  - Maximum JSON object nesting depth: `12 levels`
  - Maximum total parameter key count: `200 elements`

### SEC-006: Prompt Injection & Instruction Hijacking Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block (ENFORCE) or Scrub (SANITIZE)
- **Target Fields**: Any string argument within tool calls
- **Signatures Detected**:
  - Instruction boundary overrides: `ignore previous instructions`, `disregard all previous directions`, `system prompt override`
  - Roleplay exploits: `you are now DAN`, `developer mode enabled`, `jailbreak mode`
  - Marker injections: `[INST]`, `<|im_start|>`, `<|system|>`, `### System Instruction`
  - Hidden character bypasses: BiDi overrides (`\u202E`), zero-width space stuffing (`[\u200B\u200C\u200D\uFEFF]`)

### SEC-007: SQL & Query Injection Guard
- **Severity**: `HIGH`
- **Default Action**: Block & Isolate
- **Target Fields**: Database query strings, search criteria, filter clauses
- **Signatures Detected**:
  - Boolean tautology bypasses: `' OR '1'='1`, `OR 1=1`, `WHERE '1'='1'`, `AND true=true`
  - Union & Stacked queries: `UNION ALL SELECT`, `; DROP TABLE`, `UNION SELECT null`
  - Comment truncation: `-- `, `/* ... */`, `#` at end of clause
  - Dangerous stored procedures: `EXEC xp_cmdshell`, `EXEC sp_executesql`
  - Hex & SQL functions: `CHAR(...)`, `0x[0-9a-fA-F]+`, `SLEEP(...)`, `BENCHMARK(...)`

### SEC-008: Prototype Pollution & Object Injection Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block (ENFORCE) or Strip (SANITIZE)
- **Target Fields**: Top-level and nested parameter keys and prototypes
- **Signatures Detected**:
  - Prototype key access: `__proto__`, `constructor.prototype`, `prototype` in dot/bracket paths
  - Direct prototype tampering: parameters inheriting altered object prototypes

### SEC-009: Environment & Secrets Exfiltration Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block (ENFORCE) or Redact (SANITIZE)
- **Target Fields**: File paths, command arguments, export strings
- **Signatures Detected**:
  - Environment files: `.env`, `.env.local`, `.env.production`, `.envrc`
  - Cloud credential stores: `~/.aws/credentials`, `~/.aws/config`, `~/.azure/`, `~/.gcloud/`
  - Shell history & keys: `~/.bash_history`, `~/.zsh_history`, `~/.ssh/id_rsa`, `~/.ssh/known_hosts`
  - Environment variable access: `process.env`, `$ENV`, `${AWS_SECRET_ACCESS_KEY}`

---

## Dynamic Security Rule Synthesis

AegisMCP includes a dynamic rule synthesizer (`DynamicRuleSynthesizer`) capable of generating executable firewall rules at runtime:

1. **Schema-Driven Synthesis**: Inspects tool parameter JSON schemas (e.g. parameter names containing `sql`, `query`, `path`, `cmd`, `url`, `secret`) and synthesizes targeted validation constraints.
2. **Threat Signature Compilation**: Compiles custom regex signatures into full rule objects with automatic telemetry tracking and violations counting.
3. **Hot-Reloading**: Injected rules are immediately active in the proxy engine without requiring server restarts or connection resets.

```javascript
import { DynamicRuleSynthesizer } from 'aegis-mcp';

const synthesizer = new DynamicRuleSynthesizer(firewallEngine);
const rule = synthesizer.synthesizeFromSignature({
  name: 'Internal Token Validator',
  severity: 'HIGH',
  pattern: /int_[0-9a-f]{24}/i,
  category: 'TOKEN_LEAKAGE'
});
firewallEngine.addCustomRule(rule);
```

---

## Authoring Custom Rules

Custom rules can be added programmatically or via the Web Studio interface:

```javascript
firewall.addCustomRule({
  id: 'ORG-001',
  name: 'Restrict Internal IP Ranges',
  severity: 'HIGH',
  check: (params, toolName) => {
    const serialized = JSON.stringify(params);
    if (/corp\.internal\.net/.test(serialized)) {
      return {
        violation: true,
        signature: 'Direct Internal DNS Query Prohibited',
        culprit: 'corp.internal.net'
      };
    }
    return { violation: false };
  }
});
```
