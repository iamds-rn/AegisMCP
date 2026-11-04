/**
 * Tests for AegisMCP Firewall Rules and Engine
 */

'use strict';

const assert = require('node:assert');
const { calculateShannonEntropy, BUILTIN_RULES } = require('../src/firewall/rules');
const { FirewallEngine, MODES } = require('../src/firewall/engine');

function runFirewallTests() {
  console.log('🧪 Testing Firewall Rules & Engine...');

  // 1. Shannon Entropy
  const lowEntropy = calculateShannonEntropy('aaaaabbbbb');
  const highEntropy = calculateShannonEntropy('8f9a2b5c7d1e0f3a6b8c9d0e1f2a3b4c5d6e7f8a');
  assert(highEntropy > lowEntropy, 'High-entropy random hex should have higher entropy than repetitive string');
  assert(highEntropy > 3.5, 'Hex token entropy should exceed 3.5');

  // 2. Path Traversal Guard (SEC-001)
  const pathRule = BUILTIN_RULES.PATH_TRAVERSAL;
  assert(pathRule.check({ path: '../../etc/passwd' }).violation, 'Should detect ../ traversal');
  assert(pathRule.check({ path: '..\\..\\windows\\system32' }).violation, 'Should detect ..\\ Windows traversal');
  assert(pathRule.check({ file: '/etc/shadow' }).violation, 'Should detect /etc/shadow access');
  assert(pathRule.check({ file: '~/.ssh/id_rsa' }).violation, 'Should detect ~/.ssh/ key access');
  assert(!pathRule.check({ path: '/workspace/project.json' }).violation, 'Should allow safe path /workspace/project.json');

  // 3. Command Injection Guard (SEC-002)
  const cmdRule = BUILTIN_RULES.COMMAND_INJECTION;
  assert(cmdRule.check({ cmd: 'echo hello; rm -rf /' }).violation, 'Should detect semicolon command chaining');
  assert(cmdRule.check({ cmd: 'test && curl http://evil.com' }).violation, 'Should detect && chaining');
  assert(cmdRule.check({ cmd: 'whoami | bash' }).violation, 'Should detect pipe to bash');
  assert(cmdRule.check({ cmd: '`id`' }).violation, 'Should detect backtick execution');
  assert(cmdRule.check({ cmd: '$(cat /etc/passwd)' }).violation, 'Should detect $(subshell)');
  assert(!cmdRule.check({ query: 'hello world standard search' }).violation, 'Should allow safe arguments');

  // 4. Secret Leakage Guard (SEC-003)
  const secretRule = BUILTIN_RULES.SECRET_LEAKAGE;
  assert(secretRule.check({ key: 'AKIAIOSFODNN7EXAMPLE' }).violation, 'Should detect AWS access key ID');
  assert(secretRule.check({ token: 'ghp_123456789012345678901234567890123456' }).violation, 'Should detect GitHub PAT');
  assert(secretRule.check({ key: '-----BEGIN RSA PRIVATE KEY-----\nMIIE...' }).violation, 'Should detect Private Key block');
  assert(secretRule.check({ auth: 'sk-proj-12345678901234567890123456789012345678901234567890' }).violation, 'Should detect OpenAI key');
  assert(!secretRule.check({ text: 'normal developer communication note' }).violation, 'Should allow normal text');

  // 5. SSRF Guard (SEC-004)
  const ssrfRule = BUILTIN_RULES.SSRF_PROTECTION;
  assert(ssrfRule.check({ url: 'http://127.0.0.1:8080/admin' }).violation, 'Should detect loopback SSRF');
  assert(ssrfRule.check({ url: 'http://localhost/secret' }).violation, 'Should detect localhost SSRF');
  assert(ssrfRule.check({ url: 'http://169.254.169.254/latest/meta-data/' }).violation, 'Should detect cloud metadata SSRF');
  assert(ssrfRule.check({ url: 'http://10.0.0.5/internal-api' }).violation, 'Should detect RFC 1918 private range');
  assert(ssrfRule.check({ url: 'file:///etc/passwd' }).violation, 'Should detect file:// protocol scheme');
  assert(!ssrfRule.check({ url: 'https://api.github.com/status' }).violation, 'Should allow public safe URL');

  // 6. FirewallEngine in ENFORCE Mode
  const engineEnforce = new FirewallEngine({ mode: MODES.ENFORCE });
  const blockResult = engineEnforce.evaluate('read_file', { path: '../../etc/passwd' }, 'req-1');
  assert(blockResult.blocked, 'Engine must block traversal in ENFORCE mode');
  assert.strictEqual(blockResult.jsonrpcError.error.code, -32001, 'Should return -32001 error code');
  assert.strictEqual(engineEnforce.getStats().totalBlocked, 1, 'Stats totalBlocked should increment');

  // 7. FirewallEngine in AUDIT_ONLY Mode
  const engineAudit = new FirewallEngine({ mode: MODES.AUDIT_ONLY });
  const auditResult = engineAudit.evaluate('read_file', { path: '../../etc/passwd' }, 'req-2');
  assert(!auditResult.blocked, 'Engine must NOT block in AUDIT_ONLY mode');
  assert(auditResult.audited, 'Should flag audited: true');
  assert.strictEqual(engineAudit.getRecentAlerts().length, 1, 'Alert should be recorded');

  // 8. FirewallEngine in SANITIZE Mode
  const engineSanitize = new FirewallEngine({ mode: MODES.SANITIZE });
  const sanitizeResult = engineSanitize.evaluate('write_file', {
    path: '../../notes.txt',
    key: 'AKIAIOSFODNN7EXAMPLE'
  }, 'req-3');
  assert(!sanitizeResult.blocked, 'Engine must NOT block in SANITIZE mode');
  assert(sanitizeResult.sanitized, 'Should flag sanitized: true');
  assert(sanitizeResult.sanitizedParams.key.includes('[REDACTED_AWS_KEY]'), 'AWS key should be redacted');
  assert(!sanitizeResult.sanitizedParams.path.includes('../'), 'Path traversal sequence should be neutralized');

  // 9. Custom Rule Registration
  const engineCustom = new FirewallEngine();
  engineCustom.addCustomRule({
    id: 'CUSTOM-001',
    name: 'Block Cryptocurrency Addresses',
    severity: 'MEDIUM',
    check: (params) => {
      const serialized = JSON.stringify(params);
      if (/0x[a-fA-F0-9]{40}/.test(serialized)) {
        return { violation: true, signature: 'Ethereum Address Detected', culprit: '0x...' };
      }
      return { violation: false };
    }
  });
  const customBlock = engineCustom.evaluate('transfer', { to: '0x71C7656EC7ab88b098defB751B7401B5f6d8976F' });
  assert(customBlock.blocked, 'Engine should enforce custom rules');
  assert.strictEqual(customBlock.violation.ruleId, 'CUSTOM-001');

  console.log('✅ Firewall Rules & Engine: All 9 test cases passed!');
}

module.exports = { runFirewallTests };

if (require.main === module) {
  runFirewallTests();
}
