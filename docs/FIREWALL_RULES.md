# AegisMCP Security Rules & Threat Signatures

This document catalogs the built-in threat detection rules implemented in the AegisMCP Zero-Trust Engine.

---

## Built-In Detection Rules

### SEC-001: Path Traversal Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block & Isolate
- **Target Fields**: Any string argument within `tools/call` parameters
- **Signatures Detected**:
  - POSIX & Windows directory traversal: `../`, `..\`, `%2e%2e%2f`, `%2e%2e/`, `..;/`, `..\..\`
  - Double URL-encoded sequences: `%252e%252e%252f`, `%252e%252e/`
  - Null-byte extension truncation: `\x00`, `%00`
  - Sensitive UNIX paths: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/proc/self`, `/proc/[pid]`, `/sys/`, `/var/run/secrets`
  - User configuration and key directories: `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.bash_history`
  - Windows system roots: `C:\Windows\System32`, `\\.\`, `\etc\passwd`

### SEC-002: Command Injection Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block & Isolate
- **Target Fields**: Tool arguments, command parameters, subshell strings
- **Signatures Detected**:
  - Command chaining metacharacters: `;`, `&&`, `||`, `|`, `\n`, `\r`
  - Subshell operators: `` `command` ``, `$(command)`
  - Dangerous & recon binaries: `rm`, `cat`, `curl`, `wget`, `bash`, `sh`, `nc`, `mkfifo`, `powershell`, `python`, `whoami`, `id`, `uname`, `hostname`, `env`, `printenv`, `sudo`, `/bin/sh`, `/bin/bash`, `/usr/bin/python`
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
  - **Google API Key**: `\bAIza[0-9A-Za-z\-_]{35}\b`
  - **Stripe Live Secret Key**: `\bsk_live_[0-9a-zA-Z]{24,}\b`
  - **Hugging Face Token**: `\bhf_[a-zA-Z0-9]{34,}\b`
  - **JSON Web Token (JWT)**: `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`
  - **Slack Token**: `\bxox[baprs]-[0-9A-Za-z]{10,}\b`
  - **Private Keys**: `-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? PRIVATE KEY-----`
  - **Shannon Entropy Scanner**: Strings between 32 and 128 characters with Shannon entropy $> 4.65$ bits/char.

### SEC-004: SSRF & Cloud Metadata Protection
- **Severity**: `HIGH`
- **Default Action**: Block & Isolate
- **Target Fields**: Destination URLs, endpoint URIs, webhook parameters
- **Signatures Detected**:
  - Loopback addresses: `localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`, `[::]`, `127.0.0.0/8`
  - IPv4-mapped IPv6 loopbacks & hex: `[::ffff:127.0.0.1]`, `[::ffff:7f00:1]`
  - Cloud instance metadata services: `169.254.169.254`, `[::ffff:169.254.169.254]`, `[::ffff:a9fe:a9fe]`, `metadata.google.internal`, `100.100.100.200`
  - RFC 1918 Private Ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Dangerous URL protocols: `file://`, `gopher://`, `dict://`, `tftp://`, `sftp://`, `ldap://` (including with leading spaces)

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
  - Instruction boundary overrides: `ignore previous instructions`, `disregard all previous directions`, `system prompt override`, `ignore preceding instructions`
  - Roleplay exploits: `you are now DAN`, `developer mode enabled`, `jailbreak mode`
  - Marker injections: `[INST]`, `[/INST]`, `<|im_start|>`, `<|system|>`, `### System Instruction`, `<<SYS>>`, `<start_of_turn>`, `<end_of_turn>`
  - Hidden character bypasses: BiDi overrides (`\u202E`), zero-width space stuffing (`[\u200B\u200C\u200D\uFEFF]`)

### SEC-007: SQL & Query Injection Guard
- **Severity**: `HIGH`
- **Default Action**: Block & Isolate
- **Target Fields**: Database query strings, search criteria, filter clauses
- **Signatures Detected**:
  - Boolean tautology bypasses: `' OR '1'='1`, `OR 1=1`, `WHERE '1'='1'`, `AND true=true`
  - Destructive DML: `DELETE FROM`, `UPDATE ... SET`, `INSERT INTO`
  - Union & Stacked queries: `UNION ALL SELECT`, `; DROP TABLE`, `UNION SELECT null`
  - Blind time delay / sleep: `pg_sleep(...)`, `WAITFOR DELAY '...'`, `SLEEP(...)`, `BENCHMARK(...)`
  - Comment truncation: `-- `, `/* ... */`, `#` at end of clause
  - Dangerous stored procedures: `EXEC xp_cmdshell`, `EXEC sp_executesql`
  - Hex & SQL functions: `CHAR(...)`, `0x[0-9a-fA-F]+`

### SEC-008: Prototype Pollution & Object Injection Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block (ENFORCE) or Strip (SANITIZE)
- **Target Fields**: Top-level and nested parameter keys, own properties, and prototypes
- **Signatures Detected**:
  - Prototype key access: `__proto__`, `constructor.prototype`, `prototype` in dot/bracket paths
  - Structured nested object injection: `{ constructor: { prototype: ... } }`
  - Own property injection created via `JSON.parse` or `Object.defineProperty`

### SEC-009: Environment & Secrets Exfiltration Guard
- **Severity**: `CRITICAL`
- **Default Action**: Block (ENFORCE) or Redact (SANITIZE)
- **Target Fields**: File paths, command arguments, export strings
- **Signatures Detected**:
  - Environment files: `.env`, `.env.local`, `.env.production`, `.envrc`, `.env.staging`
  - Cloud credential stores: `~/.aws/credentials`, `~/.aws/config`, `.aws\credentials`, `.aws\config`, `~/.azure/`, `~/.gcloud/`
  - Kubernetes & Docker configs: `.kube/config`, `.kube\config`, `.docker/config.json`
  - Shell history & keys: `~/.bash_history`, `~/.zsh_history`, `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/known_hosts`
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
