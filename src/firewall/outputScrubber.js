/**
 * AegisMCP - Bidirectional Tool Output Scrubber & PII Shield
 * Inspects tool responses before they are returned to the LLM agent,
 * redacting credentials, tokens, PII, and neutralizing indirect prompt injections.
 * Zero external runtime dependencies.
 */

'use strict';

// Luhn Algorithm for Credit Card validation
function isValidLuhn(numberStr) {
  const digits = numberStr.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits.charAt(i), 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n = (n % 10) + 1;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

const REDACTION_PATTERNS = [
  {
    type: 'AWS_ACCESS_KEY',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    placeholder: '[REDACTED_BY_AEGIS_SHIELD:AWS_KEY]'
  },
  {
    type: 'GITHUB_TOKEN',
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/g,
    placeholder: '[REDACTED_BY_AEGIS_SHIELD:GITHUB_TOKEN]'
  },
  {
    type: 'PRIVATE_KEY',
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    placeholder: '[REDACTED_BY_AEGIS_SHIELD:PRIVATE_KEY]'
  },
  {
    type: 'JWT',
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    placeholder: '[REDACTED_BY_AEGIS_SHIELD:JWT]'
  },
  {
    type: 'SSN',
    regex: /\b(\d{3}-\d{2}-\d{4})\b/g,
    placeholder: '[REDACTED_BY_AEGIS_SHIELD:SSN]'
  },
  {
    type: 'INDIRECT_PROMPT_INJECTION',
    regex: /\[(?:SYSTEM NOTE|INSTRUCTION OVERRIDE|ADMIN DIRECTIVE):[\s\S]*?\]|(?:\bNew Instruction:\s*ignore\b[\s\S]*)/gi,
    placeholder: '[REDACTED_BY_AEGIS_SHIELD:INDIRECT_INJECTION]'
  }
];

// Regex matching potential credit card numbers (grouped or hyphenated)
const CC_CANDIDATE_REGEX = /\b(?:\d{4}[- ]?){3}\d{1,4}\b|\b\d{13,19}\b/g;

class OutputScrubber {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.patterns = options.patterns || REDACTION_PATTERNS;
    this.customPlaceholders = options.placeholders || {};
  }

  /**
   * Scrubs a string value of sensitive credentials, PII, and indirect injections
   */
  scrubString(str, redactions = []) {
    if (typeof str !== 'string' || str.length === 0) return str;

    let modified = str;

    // 1. Static regex patterns
    for (const pat of this.patterns) {
      modified = modified.replace(pat.regex, (match) => {
        redactions.push({ type: pat.type, matchLength: match.length });
        return pat.placeholder;
      });
    }

    // 2. Luhn-verified Credit Card scrubbing
    modified = modified.replace(CC_CANDIDATE_REGEX, (match) => {
      const stripped = match.replace(/[- ]/g, '');
      if (isValidLuhn(stripped)) {
        redactions.push({ type: 'CREDIT_CARD', matchLength: match.length });
        return '[REDACTED_BY_AEGIS_SHIELD:CREDIT_CARD]';
      }
      return match;
    });

    return modified;
  }

  /**
   * Recursively traverses and sanitizes an arbitrary payload
   */
  _deepScrub(val, redactions, seen = new WeakSet()) {
    if (val === null || val === undefined) return val;

    if (typeof val === 'string') {
      return this.scrubString(val, redactions);
    }

    if (Buffer.isBuffer(val)) {
      const str = val.toString('utf8');
      const scrubbed = this.scrubString(str, redactions);
      return Buffer.from(scrubbed, 'utf8');
    }

    if (typeof val !== 'object') {
      return val;
    }

    // Cycle detection
    if (seen.has(val)) {
      return '[Circular Reference]';
    }
    seen.add(val);

    if (Array.isArray(val)) {
      return val.map(item => this._deepScrub(item, redactions, seen));
    }

    const cleanObj = {};
    for (const [k, v] of Object.entries(val)) {
      // Disallow prototype pollution keys during clone
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      cleanObj[k] = this._deepScrub(v, redactions, seen);
    }
    return cleanObj;
  }

  /**
   * Inspects and scrubs a tool execution result
   * @param {any} result - Tool return value
   * @returns {{ scrubbed: boolean, result: any, redactionCount: number, redactions: Array }}
   */
  scrub(result) {
    if (!this.enabled || result === null || result === undefined) {
      return { scrubbed: false, result, redactionCount: 0, redactions: [] };
    }

    const redactions = [];
    const sanitized = this._deepScrub(result, redactions);

    return {
      scrubbed: redactions.length > 0,
      result: sanitized,
      redactionCount: redactions.length,
      redactions
    };
  }
}

module.exports = {
  OutputScrubber,
  isValidLuhn,
  REDACTION_PATTERNS
};
