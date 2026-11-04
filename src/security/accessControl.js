/**
 * AegisMCP - Attribute-Based Access Control (ABAC) & Human-in-the-Loop Approval Gate
 * Zero runtime dependencies (uses native node:crypto).
 */

'use strict';

const crypto = require('node:crypto');

const ERROR_CODES = {
  AEGIS_ACCESS_DENIED: -32007,
  AEGIS_AWAITING_APPROVAL: -32006
};

/**
 * AccessControlEngine evaluates role-based and attribute-based permissions
 * for callers, tools, and parameter constraints.
 */
class AccessControlEngine {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.defaultPolicy = options.defaultPolicy || 'allow'; // 'allow' or 'deny'
    // Map of role -> { allow: string[], deny: string[], constraints: Record<string, Function|Object> }
    this.roles = new Map();
    this.initDefaultRoles();
  }

  initDefaultRoles() {
    // Admin has unrestricted access
    this.registerRole('admin', {
      allow: ['*'],
      deny: []
    });

    // Developer can access standard development tools, cannot delete or export vault
    this.registerRole('developer', {
      allow: ['*'],
      deny: ['crypto_vault:export_keys', '*:format_disk', '*:drop_database'],
      constraints: {
        'virtual_fs:write_file': (params) => {
          if (!params || typeof params.path !== 'string') return true;
          // Disallow writing outside /workspace or writing sensitive files
          const forbidden = /\/(\.env|\.ssh|etc|passwd|id_rsa)/i;
          return !forbidden.test(params.path);
        }
      }
    });

    // Read-only agent role
    this.registerRole('reader', {
      allow: ['*:read*', '*:list*', '*:get*', '*:search*', '*:ping*'],
      deny: ['*:write*', '*:delete*', '*:execute*', '*:create*']
    });
  }

  registerRole(name, policy) {
    this.roles.set(name, {
      allow: Array.isArray(policy.allow) ? policy.allow : ['*'],
      deny: Array.isArray(policy.deny) ? policy.deny : [],
      constraints: policy.constraints || {}
    });
  }

  _matchesPattern(pattern, target) {
    if (pattern === '*' || pattern === target) return true;
    const regexStr = '^' + pattern.replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&').replace(/\*/g, '.*') + '$';
    return new RegExp(regexStr, 'i').test(target);
  }

  _isToolAllowed(policy, toolIdentifier) {
    // Check explicit deny list first
    for (const denyPattern of policy.deny) {
      if (this._matchesPattern(denyPattern, toolIdentifier)) {
        return false;
      }
    }
    // Check allow list
    for (const allowPattern of policy.allow) {
      if (this._matchesPattern(allowPattern, toolIdentifier)) {
        return true;
      }
    }
    return false;
  }

  checkPermission({ role = 'admin', server = 'default', tool, params = {} }) {
    if (!this.enabled) {
      return { allowed: true };
    }

    if (!tool) {
      return { allowed: false, code: ERROR_CODES.AEGIS_ACCESS_DENIED, reason: 'Tool name required for permission evaluation' };
    }

    const toolIdentifier = `${server}:${tool}`;
    const rolePolicy = this.roles.get(role);

    if (!rolePolicy) {
      if (this.defaultPolicy === 'deny') {
        return {
          allowed: false,
          code: ERROR_CODES.AEGIS_ACCESS_DENIED,
          reason: `Unknown role '${role}' denied by default policy`
        };
      }
      return { allowed: true };
    }

    // 1. Evaluate tool allow/deny patterns
    const allowed = this._isToolAllowed(rolePolicy, toolIdentifier);
    if (!allowed) {
      return {
        allowed: false,
        code: ERROR_CODES.AEGIS_ACCESS_DENIED,
        reason: `Role '${role}' is not authorized to invoke '${toolIdentifier}'`
      };
    }

    // 2. Evaluate parameter constraints
    if (rolePolicy.constraints) {
      const constraint = rolePolicy.constraints[toolIdentifier] || rolePolicy.constraints[tool];
      if (typeof constraint === 'function') {
        try {
          const pass = constraint(params);
          if (!pass) {
            return {
              allowed: false,
              code: ERROR_CODES.AEGIS_ACCESS_DENIED,
              reason: `Parameter constraint failed for '${toolIdentifier}' under role '${role}'`
            };
          }
        } catch (err) {
          return {
            allowed: false,
            code: ERROR_CODES.AEGIS_ACCESS_DENIED,
            reason: `Constraint evaluation error: ${err.message}`
          };
        }
      } else if (constraint && typeof constraint === 'object') {
        // Pattern-based parameter check
        for (const [key, pattern] of Object.entries(constraint)) {
          const val = params[key];
          if (pattern instanceof RegExp && typeof val === 'string' && !pattern.test(val)) {
            return {
              allowed: false,
              code: ERROR_CODES.AEGIS_ACCESS_DENIED,
              reason: `Parameter '${key}' does not satisfy security constraint pattern for '${toolIdentifier}'`
            };
          }
        }
      }
    }

    return { allowed: true };
  }
}

/**
 * Human-in-the-Loop Approval Gate for High-Blast-Radius Actions
 */
class ApprovalGate {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.defaultTtlMs = options.ttlMs || 300000; // 5 minutes
    this.pendingApprovals = new Map();
    this.highRiskTools = new Set(options.highRiskTools || [
      'execute_command',
      'vault_export',
      'format_disk',
      'drop_database',
      'system_shutdown',
      'deploy_production'
    ]);
  }

  isHighRisk(toolName) {
    if (!toolName) return false;
    if (this.highRiskTools.has(toolName)) return true;
    const lower = toolName.toLowerCase();
    return lower.includes('delete') || lower.includes('drop') || lower.includes('destroy') || lower.includes('export_keys');
  }

  registerHighRiskTool(toolName) {
    this.highRiskTools.add(toolName);
  }

  requestApproval({ server, tool, params = {}, caller = 'agent', reason = null, ttlMs = null }) {
    const approvalId = 'appr_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    const expiresAt = now + (ttlMs || this.defaultTtlMs);

    const record = {
      approvalId,
      server,
      tool,
      params,
      caller,
      reason: reason || `High-risk tool '${tool}' requires operator approval`,
      status: 'PENDING', // PENDING, APPROVED, REJECTED, EXPIRED
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(expiresAt).toISOString(),
      expiresAtMs: expiresAt,
      resolution: null
    };

    this.pendingApprovals.set(approvalId, record);
    return record;
  }

  getApproval(approvalId) {
    const record = this.pendingApprovals.get(approvalId);
    if (!record) return null;
    if (record.status === 'PENDING' && Date.now() > record.expiresAtMs) {
      record.status = 'EXPIRED';
    }
    return record;
  }

  approve(approvalId, approver = 'operator') {
    const record = this.getApproval(approvalId);
    if (!record) {
      return { success: false, reason: 'Approval request not found' };
    }
    if (record.status !== 'PENDING') {
      return { success: false, reason: `Approval request is already ${record.status}` };
    }

    record.status = 'APPROVED';
    record.resolution = {
      approver,
      resolvedAt: new Date().toISOString(),
      token: crypto.randomBytes(16).toString('hex')
    };

    return { success: true, record };
  }

  reject(approvalId, rejector = 'operator', reason = 'Operator rejected request') {
    const record = this.getApproval(approvalId);
    if (!record) {
      return { success: false, reason: 'Approval request not found' };
    }
    if (record.status !== 'PENDING') {
      return { success: false, reason: `Approval request is already ${record.status}` };
    }

    record.status = 'REJECTED';
    record.resolution = {
      rejector,
      reason,
      resolvedAt: new Date().toISOString()
    };

    return { success: true, record };
  }

  listPending() {
    const now = Date.now();
    const list = [];
    for (const record of this.pendingApprovals.values()) {
      if (record.status === 'PENDING') {
        if (now > record.expiresAtMs) {
          record.status = 'EXPIRED';
        } else {
          list.push(record);
        }
      }
    }
    return list;
  }

  listAll() {
    return Array.from(this.pendingApprovals.values());
  }

  cleanupExpired() {
    const now = Date.now();
    let cleaned = 0;
    for (const [id, record] of this.pendingApprovals.entries()) {
      if (record.expiresAtMs < now && record.status !== 'PENDING') {
        this.pendingApprovals.delete(id);
        cleaned++;
      }
    }
    return cleaned;
  }
}

module.exports = {
  AccessControlEngine,
  ApprovalGate,
  ERROR_CODES
};
