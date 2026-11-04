/**
 * AegisMCP - Protocol Fuzzer & Conformance Auditor
 * Automated adversarial fuzz testing, schema boundary generation, and resilience scorecard.
 */

'use strict';

class ProtocolFuzzer {
  constructor(options = {}) {
    this.timeoutMs = options.timeoutMs || 2000;
  }

  /**
   * Generates adversarial test cases for a specific tool based on its JSON Schema.
   *
   * @param {object} tool - Tool definition with name and inputSchema
   * @returns {Array<object>} List of test cases { category, name, payload, expectedBehavior }
   */
  generateTestCases(tool) {
    if (!tool || typeof tool !== 'object') return [];
    const testCases = [];
    const schema = tool.inputSchema || {};
    const properties = (schema && typeof schema.properties === 'object' && schema.properties !== null) ? schema.properties : {};
    const required = Array.isArray(schema.required) ? schema.required : [];

    // Helper to build a base valid payload
    const baseValid = {};
    for (const [key, prop] of Object.entries(properties)) {
      if (prop.type === 'string') {
        baseValid[key] = key.toLowerCase().includes('path') ? '/workspace/project.json' : 'test_value';
      } else if (prop.type === 'number' || prop.type === 'integer') {
        baseValid[key] = 10;
      } else if (prop.type === 'boolean') {
        baseValid[key] = true;
      } else if (prop.type === 'array') {
        baseValid[key] = ['item1'];
      } else if (prop.type === 'object') {
        baseValid[key] = { nested: 'value' };
      } else {
        baseValid[key] = 'sample';
      }
    }

    // 1. SCHEMA CONFORMANCE: Missing required properties
    for (const req of required) {
      const payload = { ...baseValid };
      delete payload[req];
      testCases.push({
        category: 'SCHEMA_CONFORMANCE',
        name: `Missing required property: "${req}"`,
        payload,
        expectedBehavior: 'REJECT_WITH_ERROR'
      });
    }

    // 2. NULL & UNDEFINED MUTATION
    for (const key of Object.keys(properties)) {
      const payload = { ...baseValid, [key]: null };
      testCases.push({
        category: 'NULL_MUTATION',
        name: `Explicit null passed for "${key}"`,
        payload,
        expectedBehavior: 'SAFE_HANDLE'
      });
    }

    // 3. TYPE MUTATIONS
    for (const [key, prop] of Object.entries(properties)) {
      if (prop.type === 'string') {
        testCases.push({
          category: 'TYPE_MUTATION',
          name: `Number passed to string field "${key}"`,
          payload: { ...baseValid, [key]: 123456789 },
          expectedBehavior: 'SAFE_HANDLE'
        });
        testCases.push({
          category: 'TYPE_MUTATION',
          name: `Array passed to string field "${key}"`,
          payload: { ...baseValid, [key]: ['payload1', 'payload2'] },
          expectedBehavior: 'SAFE_HANDLE'
        });
        testCases.push({
          category: 'TYPE_MUTATION',
          name: `Object passed to string field "${key}"`,
          payload: { ...baseValid, [key]: { nestedKey: 'malicious' } },
          expectedBehavior: 'SAFE_HANDLE'
        });
      } else if (prop.type === 'number' || prop.type === 'integer') {
        testCases.push({
          category: 'TYPE_MUTATION',
          name: `String passed to numeric field "${key}"`,
          payload: { ...baseValid, [key]: 'not_a_number' },
          expectedBehavior: 'SAFE_HANDLE'
        });
      }
    }

    // 4. BOUNDARY VALUES & OVERFLOW
    for (const [key, prop] of Object.entries(properties)) {
      if (prop.type === 'string') {
        testCases.push({
          category: 'BOUNDARY_VALUES',
          name: `Empty string on field "${key}"`,
          payload: { ...baseValid, [key]: '' },
          expectedBehavior: 'SAFE_HANDLE'
        });
        testCases.push({
          category: 'BOUNDARY_VALUES',
          name: `Large string (32KB buffer stress) on "${key}"`,
          payload: { ...baseValid, [key]: 'A'.repeat(32768) },
          expectedBehavior: 'SAFE_HANDLE'
        });
      } else if (prop.type === 'number' || prop.type === 'integer') {
        testCases.push({
          category: 'BOUNDARY_VALUES',
          name: `MAX_SAFE_INTEGER on "${key}"`,
          payload: { ...baseValid, [key]: Number.MAX_SAFE_INTEGER },
          expectedBehavior: 'SAFE_HANDLE'
        });
        testCases.push({
          category: 'BOUNDARY_VALUES',
          name: `Negative extreme integer on "${key}"`,
          payload: { ...baseValid, [key]: Number.MIN_SAFE_INTEGER },
          expectedBehavior: 'SAFE_HANDLE'
        });
      }
    }

    // 5. SECURITY INJECTIONS
    for (const [key, prop] of Object.entries(properties)) {
      if (prop.type === 'string') {
        // Path Traversal
        testCases.push({
          category: 'SECURITY_INJECTION',
          name: `Path Traversal (../../../../etc/passwd) on "${key}"`,
          payload: { ...baseValid, [key]: '../../../../etc/passwd' },
          expectedBehavior: 'FIREWALL_BLOCK_OR_REJECT'
        });
        testCases.push({
          category: 'SECURITY_INJECTION',
          name: `Windows Path Traversal (..\\..\\windows\\system32) on "${key}"`,
          payload: { ...baseValid, [key]: '..\\..\\windows\\system32\\cmd.exe' },
          expectedBehavior: 'FIREWALL_BLOCK_OR_REJECT'
        });

        // Command Injection
        testCases.push({
          category: 'SECURITY_INJECTION',
          name: `Command Chaining (; cat /etc/shadow) on "${key}"`,
          payload: { ...baseValid, [key]: 'legit; cat /etc/shadow || echo pwned' },
          expectedBehavior: 'FIREWALL_BLOCK_OR_REJECT'
        });
        testCases.push({
          category: 'SECURITY_INJECTION',
          name: `Subshell Execution (\$(whoami)) on "${key}"`,
          payload: { ...baseValid, [key]: '$(whoami)' },
          expectedBehavior: 'FIREWALL_BLOCK_OR_REJECT'
        });

        // Secret Leakage
        testCases.push({
          category: 'SECURITY_INJECTION',
          name: `Raw AWS Secret Key in parameter "${key}"`,
          payload: { ...baseValid, [key]: 'AKIAIOSFODNN7EXAMPLE' },
          expectedBehavior: 'FIREWALL_BLOCK_OR_REJECT'
        });

        // SSRF
        testCases.push({
          category: 'SECURITY_INJECTION',
          name: `Cloud Metadata SSRF on "${key}"`,
          payload: { ...baseValid, [key]: 'http://169.254.169.254/latest/meta-data/' },
          expectedBehavior: 'FIREWALL_BLOCK_OR_REJECT'
        });
      } else if (prop.type === 'object' && prop.properties && typeof prop.properties === 'object') {
        // Nested object property security tests
        for (const [subKey, subProp] of Object.entries(prop.properties)) {
          if (subProp && subProp.type === 'string') {
            testCases.push({
              category: 'SECURITY_INJECTION',
              name: `Path Traversal on nested "${key}.${subKey}"`,
              payload: { ...baseValid, [key]: { ...(baseValid[key] || {}), [subKey]: '../../../../etc/passwd' } },
              expectedBehavior: 'FIREWALL_BLOCK_OR_REJECT'
            });
            testCases.push({
              category: 'SECURITY_INJECTION',
              name: `Command Chaining on nested "${key}.${subKey}"`,
              payload: { ...baseValid, [key]: { ...(baseValid[key] || {}), [subKey]: '; cat /etc/shadow' } },
              expectedBehavior: 'FIREWALL_BLOCK_OR_REJECT'
            });
          }
        }
      }
    }

    // 6. UNICODE & ENCODING CHAOS
    for (const [key, prop] of Object.entries(properties)) {
      if (prop.type === 'string') {
        testCases.push({
          category: 'UNICODE_CHAOS',
          name: `Null Byte Injection (\\x00) in "${key}"`,
          payload: { ...baseValid, [key]: 'clean_prefix\x00malicious_suffix' },
          expectedBehavior: 'SAFE_HANDLE'
        });
        testCases.push({
          category: 'UNICODE_CHAOS',
          name: `BiDi RTL Override in "${key}"`,
          payload: { ...baseValid, [key]: '\u202Eexe.codegood\u202C' },
          expectedBehavior: 'SAFE_HANDLE'
        });
        testCases.push({
          category: 'UNICODE_CHAOS',
          name: `Zero-Width Non-Joiner Injection in "${key}"`,
          payload: { ...baseValid, [key]: 'adm\u200Cin' },
          expectedBehavior: 'SAFE_HANDLE'
        });
        testCases.push({
          category: 'UNICODE_CHAOS',
          name: `High Astral Emoji Cascade in "${key}"`,
          payload: { ...baseValid, [key]: '🛡️⚡🔥🚀🤖'.repeat(20) },
          expectedBehavior: 'SAFE_HANDLE'
        });
      }
    }

    return testCases;
  }

  /**
   * Executes fuzzing suite against a tool invoker.
   *
   * @param {object} tool - Tool definition
   * @param {Function} invokerFn - async (toolName, payload) => result
   * @param {object} firewallEngine - Optional FirewallEngine to evaluate in-line protection
   */
  async runAudit(tool, invokerFn, firewallEngine = null) {
    const testCases = this.generateTestCases(tool);
    const results = [];
    let passedCount = 0;
    let blockedCount = 0;
    let failedCount = 0;

    const startTime = Date.now();

    for (const tc of testCases) {
      const testResult = {
        name: tc.name,
        category: tc.category,
        payload: tc.payload,
        status: 'PENDING',
        durationMs: 0,
        details: null
      };

      const caseStart = Date.now();

      try {
        // If firewall is attached, check firewall first
        let firewallResult = null;
        if (firewallEngine) {
          firewallResult = firewallEngine.evaluate(tool.name, tc.payload);
        }

        if (firewallResult && firewallResult.blocked) {
          testResult.status = 'BLOCKED_BY_FIREWALL';
          testResult.details = `Aegis Firewall intercepted payload: [${firewallResult.violation.ruleId}] ${firewallResult.violation.signature}`;
          blockedCount++;
          passedCount++; // Blocking an adversarial attack is a success!
        } else {
          // Send to tool invoker
          const response = await Promise.race([
            invokerFn(tool.name, tc.payload),
            new Promise((_, reject) => setTimeout(() => reject(new Error('EXECUTION_TIMEOUT')), this.timeoutMs))
          ]);

          testResult.status = 'HANDLED_GRACEFULLY';
          testResult.details = 'Target executed or validated safely without fatal crash.';
          passedCount++;
        }
      } catch (err) {
        const msg = (err && err.message) ? err.message.toLowerCase() : '';
        if (msg.includes('execution_timeout')) {
          testResult.status = 'TIMEOUT_DoS_RISK';
          testResult.details = `Execution exceeded ${this.timeoutMs}ms limit`;
          failedCount++;
        } else if (
          msg.includes('not found') ||
          msg.includes('required') ||
          msg.includes('invalid') ||
          msg.includes('cannot') ||
          msg.includes('must be') ||
          msg.includes('missing') ||
          msg.includes('validation') ||
          msg.includes('forbidden') ||
          msg.includes('denied') ||
          msg.includes('unauthorized') ||
          msg.includes('type error') ||
          msg.includes('syntax')
        ) {
          // Clean functional validation rejection
          testResult.status = 'VALIDATION_REJECTED';
          testResult.details = `Target rejected invalid payload with clean error: "${err.message}"`;
          passedCount++;
        } else {
          // Potentially unhandled exception / crash
          testResult.status = 'POTENTIAL_ANOMALY';
          testResult.details = `Unhandled exception: ${err.message}`;
          failedCount++;
        }
      }

      testResult.durationMs = Date.now() - caseStart;
      results.push(testResult);
    }

    const totalDuration = Date.now() - startTime;
    const totalTests = testCases.length;
    const scorePct = totalTests > 0 ? Math.round((passedCount / totalTests) * 100) : 100;

    let grade = 'F';
    if (scorePct >= 98) grade = 'A+';
    else if (scorePct >= 90) grade = 'A';
    else if (scorePct >= 80) grade = 'B';
    else if (scorePct >= 65) grade = 'C';
    else if (scorePct >= 50) grade = 'D';

    return {
      toolName: tool.name,
      totalTests,
      passedCount,
      blockedCount,
      failedCount,
      scorePct,
      grade,
      totalDurationMs: totalDuration,
      auditTimestamp: new Date().toISOString(),
      results
    };
  }

  /**
   * Generates a readable Markdown scorecard from audit results.
   */
  generateMarkdownReport(audit) {
    return `# AegisMCP Security & Resilience Audit Report: ${audit.toolName}

**Audit Timestamp:** ${audit.auditTimestamp}  
**Overall Grade:** **${audit.grade}** (${audit.scorePct}%)  
**Total Adversarial Vectors:** ${audit.totalTests}  
- **Passed / Handled Gracefully:** ${audit.passedCount}  
- **Intercepted by Firewall:** ${audit.blockedCount}  
- **Failed / Anomalies:** ${audit.failedCount}  
- **Total Duration:** ${audit.totalDurationMs}ms  

---

## Breakdown by Test Vector

| Test Name | Category | Status | Latency |
| :--- | :--- | :--- | :--- |
${audit.results
  .map(
    r =>
      `| ${r.name.replace(/\|/g, '\\|')} | \`${r.category}\` | **${r.status}** | ${r.durationMs}ms |`
  )
  .join('\n')}

---

*Generated by AegisMCP Protocol Fuzzer & Conformance Auditor v1.0.0*
`;
  }
}

module.exports = {
  ProtocolFuzzer
};
