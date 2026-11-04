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
