/**
 * AegisMCP - Zero-Trust Tool Firewall Engine
 * High-performance policy evaluation, real-time threat neutralization, and telemetry.
 */

'use strict';

const { BUILTIN_RULES } = require('./rules');
const { ERROR_CODES, createError } = require('../protocol/jsonrpc');

const MODES = {
  ENFORCE: 'ENFORCE',       // Drop/block request immediately with JSON-RPC error
  AUDIT_ONLY: 'AUDIT_ONLY', // Allow through, log high-severity alert to ledger
  SANITIZE: 'SANITIZE'      // Mask secrets, neutralize traversal sequences, allow through
};

class FirewallEngine {
  constructor(options = {}) {
    this.mode = options.mode || MODES.ENFORCE;
    this.enabledRules = new Map();
    this.customRules = new Map();

    // Initialize built-in rules
    for (const [key, rule] of Object.entries(BUILTIN_RULES)) {
      this.enabledRules.set(rule.id, {
        ...rule,
        key,
        enabled: true
      });
    }

    // Telemetry & metrics
    this.stats = {
      totalEvaluated: 0,
      totalPassed: 0,
      totalBlocked: 0,
      totalSanitized: 0,
      violationsByRule: {},
      violationsByTool: {},
      startTime: Date.now()
    };

    // Bounded alert log (last 50 alerts)
    this.recentAlerts = [];
    this.maxAlerts = 50;
  }

  setMode(mode) {
    if (!MODES[mode]) {
      throw new Error(`Invalid firewall mode: ${mode}. Must be ENFORCE, AUDIT_ONLY, or SANITIZE.`);
    }
    this.mode = mode;
  }

  enableRule(ruleId) {
    if (this.enabledRules.has(ruleId)) {
      this.enabledRules.get(ruleId).enabled = true;
    } else if (this.customRules.has(ruleId)) {
      this.customRules.get(ruleId).enabled = true;
    }
  }

  disableRule(ruleId) {
    if (this.enabledRules.has(ruleId)) {
      this.enabledRules.get(ruleId).enabled = false;
    } else if (this.customRules.has(ruleId)) {
      this.customRules.get(ruleId).enabled = false;
    }
  }

  addCustomRule(rule) {
    if (!rule.id || !rule.name || typeof rule.check !== 'function') {
      throw new Error('Custom rule must have id, name, and check(params, toolName) function');
    }
    this.customRules.set(rule.id, {
      ...rule,
      enabled: true,
      custom: true
    });
  }

  /**
   * Sanitizes input parameters by masking secrets and neutralizing dangerous patterns.
   */
  sanitizeParams(params) {
    if (!params || typeof params !== 'object') return params;
    let serialized;
    try {
      serialized = JSON.stringify(params);
    } catch {
      return params;
    }

    // Scrub secrets
    serialized = serialized.replace(/\b(AKIA[0-9A-Z]{16})\b/g, '[REDACTED_AWS_KEY]');
    serialized = serialized.replace(/\b(ghp_[A-Za-z0-9_]{36,})\b/g, '[REDACTED_GH_TOKEN]');
    serialized = serialized.replace(/\b(sk-[A-Za-z0-9]{32,})\b/g, '[REDACTED_OPENAI_KEY]');
    serialized = serialized.replace(/-----BEGIN[A-Z0-9_\-\s]+PRIVATE KEY-----[\s\S]*?-----END[A-Z0-9_\-\s]+PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]');

    // Neutralize directory traversal in string values
    serialized = serialized.replace(/\.\.\//g, './');
    serialized = serialized.replace(/\.\.\\/g, '.\\');

    try {
      return JSON.parse(serialized);
    } catch {
      return params;
    }
  }

  /**
   * Evaluates an incoming tool call request against all active rules.
   *
   * @param {string} toolName - Name of the MCP tool being called
   * @param {object} params - Arguments object passed to the tool
   * @param {string|number} requestId - JSON-RPC request ID
   * @returns {object} Evaluation result
   */
  evaluate(toolName, params = {}, requestId = null) {
    toolName = toolName || 'unknown_tool';
    const effectiveParams = (params !== null && typeof params === 'object') ? params : {};
    this.stats.totalEvaluated++;

    const allRules = [
      ...Array.from(this.enabledRules.values()),
      ...Array.from(this.customRules.values())
    ];

    for (const rule of allRules) {
      if (!rule.enabled) continue;

      let result;
      try {
        result = rule.check(effectiveParams, toolName);
      } catch (err) {
        // Fall-safe: if rule check throws, log and flag
        result = {
          violation: true,
          ruleId: rule.id,
          signature: `Rule Evaluation Exception: ${err.message}`,
          culprit: 'Internal Engine Check'
        };
      }

      if (result && result.violation) {
        // Track violation
        this.stats.violationsByRule[rule.id] = (this.stats.violationsByRule[rule.id] || 0) + 1;
        this.stats.violationsByTool[toolName] = (this.stats.violationsByTool[toolName] || 0) + 1;

        const alert = {
          timestamp: new Date().toISOString(),
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          toolName,
          signature: result.signature,
          culprit: result.culprit,
          mode: this.mode
        };

        this.recentAlerts.unshift(alert);
        if (this.recentAlerts.length > this.maxAlerts) {
          this.recentAlerts.pop();
        }

        if (this.mode === MODES.ENFORCE) {
          this.stats.totalBlocked++;
          return {
            allowed: false,
            blocked: true,
            mode: this.mode,
            violation: alert,
            jsonrpcError: createError(
              requestId,
              ERROR_CODES.AEGIS_POLICY_VIOLATION,
              `AegisMCP Security Firewall Block: [${rule.id}] ${rule.name} triggered. Signature: ${result.signature}`,
              {
                ruleId: rule.id,
                ruleName: rule.name,
                severity: rule.severity,
                signature: result.signature,
                culprit: result.culprit,
                recommendation: 'Modify tool arguments to comply with security policy.'
              }
            )
          };
        } else if (this.mode === MODES.SANITIZE) {
          this.stats.totalSanitized++;
          const sanitized = this.sanitizeParams(effectiveParams);
          return {
            allowed: true,
            blocked: false,
            sanitized: true,
            mode: this.mode,
            violation: alert,
            sanitizedParams: sanitized
          };
        } else {
          // AUDIT_ONLY
          this.stats.totalPassed++;
          return {
            allowed: true,
            blocked: false,
            audited: true,
            mode: this.mode,
            violation: alert
          };
        }
      }
    }

    this.stats.totalPassed++;
    return {
      allowed: true,
      blocked: false,
      mode: this.mode,
      violation: null
    };
  }

  getStats() {
    return {
      ...this.stats,
      uptimeSeconds: Math.floor((Date.now() - this.stats.startTime) / 1000),
      rulesCount: this.enabledRules.size + this.customRules.size,
      activeMode: this.mode
    };
  }

  getRecentAlerts() {
    return [...this.recentAlerts];
  }

  resetStats() {
    this.stats.totalEvaluated = 0;
    this.stats.totalPassed = 0;
    this.stats.totalBlocked = 0;
    this.stats.totalSanitized = 0;
    this.stats.violationsByRule = {};
    this.stats.violationsByTool = {};
    this.recentAlerts = [];
  }
}

module.exports = {
  MODES,
  FirewallEngine
};
