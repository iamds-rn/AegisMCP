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

/**
 * Sliding-Window Token Bucket Rate Limiter
 * Combines token bucket burst tolerance with sliding-window rolling request boundary enforcement.
 */
class TokenBucketRateLimiter {
  /**
   * @param {object} [options]
   * @param {boolean} [options.enabled=true] - Whether rate limiting is actively enforced
   * @param {number} [options.capacity=60] - Maximum burst capacity of the token bucket
   * @param {number} [options.refillRate=60] - Number of tokens replenished per windowMs
   * @param {number} [options.windowMs=60000] - Rolling sliding window in milliseconds (default: 60s)
   * @param {number} [options.cost=1] - Default token cost per consumption
   * @param {object} [options.toolLimits={}] - Custom per-tool limits override { [toolName]: { capacity, refillRate, windowMs } }
   * @param {Function} [options.timeProvider=Date.now] - Clock function for deterministic testing
   */
  constructor(options = {}) {
    this.enabled = options.enabled !== undefined ? !!options.enabled : true;
    this.capacity = typeof options.capacity === 'number' && options.capacity > 0 ? options.capacity : 60;
    this.refillRate = typeof options.refillRate === 'number' && options.refillRate > 0 ? options.refillRate : this.capacity;
    this.windowMs = typeof options.windowMs === 'number' && options.windowMs > 0 ? options.windowMs : 60000;
    this.defaultCost = typeof options.cost === 'number' && options.cost > 0 ? options.cost : 1;
    this.toolLimits = options.toolLimits ? { ...options.toolLimits } : {};
    this.timeProvider = typeof options.timeProvider === 'function' ? options.timeProvider : Date.now;

    // Map of key -> bucket state
    this.buckets = new Map();
  }

  /**
   * Configures or updates rate limiter options dynamically
   */
  configure(options = {}) {
    const oldCapacity = this.capacity;
    if (options.enabled !== undefined) this.enabled = !!options.enabled;
    if (typeof options.capacity === 'number' && options.capacity > 0) {
      this.capacity = options.capacity;
      const delta = this.capacity - oldCapacity;
      for (const bucket of this.buckets.values()) {
        bucket.capacity = this.capacity;
        if (delta > 0) {
          bucket.tokens = Math.min(bucket.capacity, bucket.tokens + delta);
        }
      }
    }
    if (typeof options.refillRate === 'number' && options.refillRate > 0) {
      this.refillRate = options.refillRate;
      for (const bucket of this.buckets.values()) {
        bucket.refillRate = this.refillRate;
      }
    }
    if (typeof options.windowMs === 'number' && options.windowMs > 0) {
      this.windowMs = options.windowMs;
      for (const bucket of this.buckets.values()) {
        bucket.windowMs = this.windowMs;
      }
    }
    if (typeof options.cost === 'number' && options.cost > 0) this.defaultCost = options.cost;
    if (options.toolLimits) Object.assign(this.toolLimits, options.toolLimits);
    if (typeof options.timeProvider === 'function') this.timeProvider = options.timeProvider;
    if (options.reset) {
      this.reset();
    }
  }

  /**
   * Retrieves or initializes the state for a given rate limiting key
   */
  _getOrCreateBucket(key, now) {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= 5000) {
        this.prune();
        if (this.buckets.size >= 5000) {
          const oldestKey = this.buckets.keys().next().value;
          if (oldestKey) this.buckets.delete(oldestKey);
        }
      }
      const custom = this.toolLimits[key] || {};
      const capacity = custom.capacity || this.capacity;
      const refillRate = custom.refillRate || this.refillRate;
      const windowMs = custom.windowMs || this.windowMs;

      bucket = {
        tokens: capacity,
        lastRefill: now,
        capacity,
        refillRate,
        windowMs,
        history: []
      };
      this.buckets.set(key, bucket);
    }
    return bucket;
  }

  /**
   * Refills tokens based on elapsed time and purges expired history records outside the sliding window
   */
  _updateBucket(bucket, now) {
    const elapsed = Math.max(0, now - bucket.lastRefill);
    if (elapsed > 0) {
      const tokensToAdd = (elapsed * bucket.refillRate) / bucket.windowMs;
      bucket.tokens = Math.min(bucket.capacity, bucket.tokens + tokensToAdd);
      bucket.lastRefill = now;
    }

    const windowStart = now - bucket.windowMs;
    while (bucket.history.length > 0 && bucket.history[0].timestamp <= windowStart) {
      bucket.history.shift();
    }
  }

  /**
   * Evaluates and consumes tokens if available under sliding-window constraints
   *
   * @param {string} [key='global']
   * @param {number} [cost]
   * @param {number} [now]
   * @returns {object} { allowed, remaining, limit, windowMs, retryAfterMs, resetMs }
   */
  consume(key = 'global', cost = null, now = null) {
    if (!this.enabled) {
      return {
        allowed: true,
        remaining: this.capacity,
        limit: this.capacity,
        windowMs: this.windowMs,
        retryAfterMs: 0,
        resetMs: 0
      };
    }

    const currentTime = now !== null ? now : this.timeProvider();
    const bucket = this._getOrCreateBucket(key, currentTime);
    this._updateBucket(bucket, currentTime);

    const effectiveCost = typeof cost === 'number' && cost > 0 ? cost : this.defaultCost;

    if (bucket.tokens >= effectiveCost) {
      bucket.tokens -= effectiveCost;
      bucket.history.push({ timestamp: currentTime, cost: effectiveCost });

      const oldestInWindow = bucket.history[0];
      const resetMs = oldestInWindow ? Math.max(0, oldestInWindow.timestamp + bucket.windowMs - currentTime) : 0;

      return {
        allowed: true,
        remaining: Math.max(0, Math.floor(bucket.tokens)),
        limit: bucket.capacity,
        windowMs: bucket.windowMs,
        retryAfterMs: 0,
        resetMs
      };
    }

    // Rate limit exceeded: calculate deterministic retryAfterMs
    const tokensNeeded = effectiveCost - bucket.tokens;
    const retryAfterMs = Math.max(
      1,
      Math.ceil((tokensNeeded * bucket.windowMs) / bucket.refillRate)
    );

    const oldest = bucket.history[0];
    const timeForWindowExpiry = oldest
      ? Math.max(0, oldest.timestamp + bucket.windowMs - currentTime)
      : retryAfterMs;

    return {
      allowed: false,
      remaining: Math.max(0, Math.floor(bucket.tokens)),
      limit: bucket.capacity,
      windowMs: bucket.windowMs,
      retryAfterMs,
      resetMs: timeForWindowExpiry
    };
  }

  /**
   * Inspects rate limit state without consuming tokens
   */
  check(key = 'global', now = null) {
    const currentTime = now !== null ? now : this.timeProvider();
    const bucket = this._getOrCreateBucket(key, currentTime);
    this._updateBucket(bucket, currentTime);
    const windowConsumed = bucket.history.reduce((acc, h) => acc + h.cost, 0);

    return {
      tokens: bucket.tokens,
      remaining: Math.max(0, Math.floor(bucket.tokens)),
      limit: bucket.capacity,
      windowMs: bucket.windowMs,
      windowConsumed,
      historyCount: bucket.history.length
    };
  }

  /**
   * Resets rate limit for a specific key, or all keys if omitted
   */
  reset(key = null) {
    if (key) {
      this.buckets.delete(key);
    } else {
      this.buckets.clear();
    }
  }

  /**
   * Removes inactive buckets older than maxAgeMs
   */
  prune(maxAgeMs = 300000) {
    const now = this.timeProvider();
    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > maxAgeMs && bucket.history.length === 0) {
        this.buckets.delete(key);
      }
    }
  }

  getStats() {
    return {
      enabled: this.enabled,
      defaultCapacity: this.capacity,
      defaultRefillRate: this.refillRate,
      defaultWindowMs: this.windowMs,
      activeBuckets: this.buckets.size
    };
  }
}

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

    // Sliding-Window Token Bucket Rate Limiter
    const rateLimitConfig = options.rateLimit;
    if (options.rateLimiter) {
      this.rateLimiter = options.rateLimiter;
    } else if (rateLimitConfig) {
      const opts = typeof rateLimitConfig === 'object' ? rateLimitConfig : {};
      this.rateLimiter = new TokenBucketRateLimiter({
        enabled: opts.enabled !== false,
        ...opts
      });
    } else {
      this.rateLimiter = new TokenBucketRateLimiter({ enabled: false });
    }

    // Telemetry & metrics
    this.stats = {
      totalEvaluated: 0,
      totalPassed: 0,
      totalBlocked: 0,
      totalSanitized: 0,
      totalRateLimited: 0,
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

  setRateLimit(config = {}) {
    if (config === false) {
      this.rateLimiter.enabled = false;
      return;
    }
    if (config === true) {
      this.rateLimiter.enabled = true;
      return;
    }
    this.rateLimiter.configure(config);
    if (config.enabled !== undefined) {
      this.rateLimiter.enabled = !!config.enabled;
    } else {
      this.rateLimiter.enabled = true;
    }
  }

  getRateLimitStatus(key = 'global') {
    return this.rateLimiter ? this.rateLimiter.check(key) : null;
  }

  resetRateLimit(key = null) {
    if (this.rateLimiter) this.rateLimiter.reset(key);
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

  toggleRule(ruleId) {
    if (this.enabledRules.has(ruleId)) {
      const rule = this.enabledRules.get(ruleId);
      rule.enabled = !rule.enabled;
      return rule.enabled;
    } else if (this.customRules.has(ruleId)) {
      const rule = this.customRules.get(ruleId);
      rule.enabled = !rule.enabled;
      return rule.enabled;
    }
    throw new Error(`Rule not found: ${ruleId}`);
  }

  addCustomRule(rule) {
    if (!rule.id || !rule.name || typeof rule.check !== 'function') {
      throw new Error('Custom rule must have id, name, and check(params, toolName) function');
    }
    this.customRules.set(rule.id, {
      ...rule,
      enabled: rule.enabled !== undefined ? rule.enabled : true,
      custom: true
    });
  }

  removeCustomRule(ruleId) {
    return this.customRules.delete(ruleId);
  }

  getAllRules() {
    const list = [];
    for (const rule of this.enabledRules.values()) {
      list.push({
        id: rule.id,
        name: rule.name,
        severity: rule.severity,
        description: rule.description,
        enabled: rule.enabled,
        custom: false,
        violations: this.stats.violationsByRule[rule.id] || 0
      });
    }
    for (const rule of this.customRules.values()) {
      list.push({
        id: rule.id,
        name: rule.name,
        severity: rule.severity,
        description: rule.description,
        enabled: rule.enabled,
        custom: true,
        violations: this.stats.violationsByRule[rule.id] || 0
      });
    }
    return list;
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

    // Neutralize prompt injection phrases
    serialized = serialized.replace(/(?:ignore|disregard|forget|skip)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|directives|rules)\b/gi, '[REDACTED_PROMPT_OVERRIDE]');
    serialized = serialized.replace(/(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>)/gi, '[REDACTED_DELIMITER]');

    // Neutralize prototype pollution
    serialized = serialized.replace(/"__proto__"/g, '"__safe_proto__"');
    serialized = serialized.replace(/"constructor\.prototype"/g, '"constructor.safe_prototype"');

    // Neutralize sensitive file exfiltration targets
    serialized = serialized.replace(/\.env(\.(local|production|development|test))?/gi, '[REDACTED_ENV_TARGET]');
    serialized = serialized.replace(/id_(rsa|ed25519|ecdsa)/gi, '[REDACTED_SSH_KEY]');

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
  evaluate(toolName, params = {}, requestId = null, options = {}) {
    toolName = toolName || 'unknown_tool';
    const effectiveParams = (params !== null && typeof params === 'object') ? params : {};
    this.stats.totalEvaluated++;

    // 1. Sliding-Window Token Bucket Rate Limiting Gate
    if (this.rateLimiter && this.rateLimiter.enabled) {
      const rateKey = (options && (options.rateLimitKey || options.clientId || options.key)) || toolName;
      const cost = (options && options.cost) || 1;
      const now = options && options.now;
      const rateResult = this.rateLimiter.consume(rateKey, cost, now);

      if (!rateResult.allowed) {
        this.stats.totalRateLimited = (this.stats.totalRateLimited || 0) + 1;
        this.stats.violationsByTool[toolName] = (this.stats.violationsByTool[toolName] || 0) + 1;

        const alert = {
          timestamp: new Date().toISOString(),
          ruleId: 'RATE-LIMIT',
          ruleName: 'Rate Limit Guard',
          severity: 'HIGH',
          toolName,
          signature: `Sliding-window rate limit exceeded for "${rateKey}". Limit: ${rateResult.limit} per ${rateResult.windowMs}ms. Remaining: 0. Retry after ${rateResult.retryAfterMs}ms.`,
          culprit: `${toolName} invocation frequency`,
          mode: this.mode,
          retryAfterMs: rateResult.retryAfterMs
        };

        this.recentAlerts.unshift(alert);
        if (this.recentAlerts.length > this.maxAlerts) {
          this.recentAlerts.pop();
        }

        if (this.mode === MODES.ENFORCE || this.mode === MODES.SANITIZE) {
          this.stats.totalBlocked++;
          return {
            allowed: false,
            blocked: true,
            rateLimited: true,
            mode: this.mode,
            violation: alert,
            retryAfterMs: rateResult.retryAfterMs,
            jsonrpcError: createError(
              requestId,
              ERROR_CODES.AEGIS_RATE_LIMIT_EXCEEDED,
              `AegisMCP Security Firewall Rate Limit: Tool call volume exceeded threshold for "${rateKey}". Try again in ${rateResult.retryAfterMs}ms.`,
              {
                ruleId: 'RATE-LIMIT',
                toolName,
                rateLimitKey: rateKey,
                limit: rateResult.limit,
                remaining: rateResult.remaining,
                windowMs: rateResult.windowMs,
                retryAfterMs: rateResult.retryAfterMs,
                recommendation: 'Reduce tool invocation frequency or increase token bucket capacity.'
              }
            )
          };
        } else {
          // AUDIT_ONLY
          this.stats.totalPassed++;
          return {
            allowed: true,
            blocked: false,
            audited: true,
            rateLimited: true,
            mode: this.mode,
            violation: alert,
            retryAfterMs: rateResult.retryAfterMs
          };
        }
      }
    }

    // 2. Rule evaluation (built-in and custom rules)
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
      activeMode: this.mode,
      rateLimiting: this.rateLimiter ? this.rateLimiter.getStats() : null
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
    this.stats.totalRateLimited = 0;
    this.stats.violationsByRule = {};
    this.stats.violationsByTool = {};
    this.recentAlerts = [];
    if (this.rateLimiter) this.rateLimiter.reset();
  }
}

module.exports = {
  MODES,
  FirewallEngine,
  TokenBucketRateLimiter
};
