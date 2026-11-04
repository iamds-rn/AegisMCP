/**
 * AegisMCP - Security Rules & Threat Signatures
 * Comprehensive detection patterns for Tool Use Firewall.
 */

'use strict';

/**
 * Calculates Shannon entropy of a string to detect high-entropy secrets and random keys.
 */
function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0;
  const frequencies = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    frequencies[ch] = (frequencies[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in frequencies) {
    const p = frequencies[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Recursively traverses any data structure to extract all strings with cycle detection.
 */
function extractAllStrings(obj, depth = 0, maxDepth = 15, visited = new Set()) {
  const strings = [];
  if (depth > maxDepth || obj === null || obj === undefined) return strings;
  if (typeof obj === 'string') {
    strings.push(obj);
  } else if (Array.isArray(obj)) {
    if (visited.has(obj)) return strings;
    visited.add(obj);
    for (const item of obj) {
      strings.push(...extractAllStrings(item, depth + 1, maxDepth, visited));
    }
  } else if (typeof obj === 'object') {
    if (visited.has(obj)) return strings;
    visited.add(obj);
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        strings.push(key);
        strings.push(...extractAllStrings(obj[key], depth + 1, maxDepth, visited));
      }
    }
  }
  return strings;
}

/**
 * Computes maximum nesting depth of an object with cycle detection.
 */
function getObjectDepth(obj, visited = new Set(), depth = 0, maxAllowedDepth = 25) {
  if (obj === null || typeof obj !== 'object' || depth > maxAllowedDepth) return 0;
  if (visited.has(obj)) return 0;
  visited.add(obj);

  let maxChildDepth = 0;
  for (const key of Object.keys(obj)) {
    maxChildDepth = Math.max(maxChildDepth, getObjectDepth(obj[key], visited, depth + 1, maxAllowedDepth));
  }
  return 1 + maxChildDepth;
}

const BUILTIN_RULES = {
  PATH_TRAVERSAL: {
    id: 'SEC-001',
    name: 'Path Traversal Guard',
    severity: 'CRITICAL',
    description: 'Prevents unauthorized file system directory traversal, relative escaping, and sensitive system file access.',
    check: (params) => {
      const strings = extractAllStrings(params);
      const traversalRegex = /(\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e\/|\.\.;\/)/i;
      const sensitiveFiles = /(\/etc\/(passwd|shadow|hosts|sudoers)|\/proc\/(self|\d+)|\/sys\/|\/var\/run\/secrets|~?\/\.(ssh|aws|gnupg|bash_history)|[c-z]:[/\\]windows[/\\]system32)/i;

      for (const str of strings) {
        if (traversalRegex.test(str)) {
          return {
            violation: true,
            ruleId: 'SEC-001',
            signature: 'Directory Traversal Sequence (..)',
            culprit: str.length > 80 ? str.slice(0, 77) + '...' : str
          };
        }
        if (sensitiveFiles.test(str)) {
          return {
            violation: true,
            ruleId: 'SEC-001',
            signature: 'Sensitive OS Path Reference',
            culprit: str.length > 80 ? str.slice(0, 77) + '...' : str
          };
        }
      }
      return { violation: false };
    }
  },

  COMMAND_INJECTION: {
    id: 'SEC-002',
    name: 'Command Injection Guard',
    severity: 'CRITICAL',
    description: 'Detects shell metacharacter injection, subshell execution, and arbitrary command chaining.',
    check: (params, toolName) => {
      // If the tool is a known shell execution tool or passes arguments to a shell
      const strings = extractAllStrings(params);
      const dangerousPatterns = [
        /(;\s*(?:rm|cat|bash|sh|curl|wget|nc|mkfifo|powershell|python|ruby)\b)/i,
        /(&&\s*(?:rm|cat|bash|sh|curl|wget|nc|mkfifo|powershell|python|ruby)\b)/i,
        /(\|\|\s*(?:rm|cat|bash|sh|curl|wget|nc|mkfifo|powershell|python|ruby)\b)/i,
        /(\|\s*(?:bash|sh|curl|wget|nc|powershell)\b)/i,
        /(`[^`]+`|\$\([^)]+\))/, // backticks or $(subshell)
        /(>\s*\/dev\/(?:tcp|udp)\/)/i, // reverse shell redirection
        /(\b(?:eval|exec)\s*\([^)]*\))/i
      ];

      for (const str of strings) {
        for (const pattern of dangerousPatterns) {
          if (pattern.test(str)) {
            return {
              violation: true,
              ruleId: 'SEC-002',
              signature: 'Shell Metacharacter / Command Chaining',
              culprit: str.length > 80 ? str.slice(0, 77) + '...' : str
            };
          }
        }
      }
      return { violation: false };
    }
  },

  SECRET_LEAKAGE: {
    id: 'SEC-003',
    name: 'Credential & Secret Leakage Guard',
    severity: 'HIGH',
    description: 'Detects API keys, cryptographic private keys, cloud tokens, and high-entropy secrets in arguments or tool responses.',
    check: (params) => {
      const strings = extractAllStrings(params);
      const secretPatterns = [
        { name: 'AWS Access Key ID', regex: /\b(AKIA[0-9A-Z]{16})\b/ },
        { name: 'GitHub Personal Access Token', regex: /\b(ghp_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/ },
        { name: 'Private Key Block', regex: /-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?PRIVATE KEY-----/ },
        { name: 'OpenAI API Key', regex: /\b(sk-[A-Za-z0-9]{32,}|sk-proj-[A-Za-z0-9_-]{40,})\b/ },
        { name: 'Anthropic API Key', regex: /\b(sk-ant-[A-Za-z0-9_-]{30,})\b/ },
        { name: 'Slack Token', regex: /\b(xox[baprs]-[0-9A-Za-z]{10,})\b/ }
      ];

      for (const str of strings) {
        for (const { name, regex } of secretPatterns) {
          if (regex.test(str)) {
            return {
              violation: true,
              ruleId: 'SEC-003',
              signature: `Credential Leak: ${name}`,
              culprit: str.slice(0, 8) + '...' + str.slice(-4)
            };
          }
        }

        // Entropy scanning for potential raw secrets (>32 chars, entropy > 4.65)
        if (str.length >= 32 && str.length <= 128 && !str.includes(' ') && !str.includes('/') && !str.includes(':')) {
          const entropy = calculateShannonEntropy(str);
          if (entropy > 4.65) {
            return {
              violation: true,
              ruleId: 'SEC-003',
              signature: `High Entropy Token (Entropy: ${entropy.toFixed(2)})`,
              culprit: str.slice(0, 6) + '...' + str.slice(-4)
            };
          }
        }
      }
      return { violation: false };
    }
  },

  SSRF_PROTECTION: {
    id: 'SEC-004',
    name: 'Server-Side Request Forgery (SSRF) Guard',
    severity: 'HIGH',
    description: 'Prevents AI tools from sending requests to loopback, link-local, cloud metadata services, and internal RFC 1918 networks.',
    check: (params) => {
      const strings = extractAllStrings(params);
      const urlRegex = /https?:\/\/[^\s/$.?#].[^\s]*/i;
      const dangerousProtocols = /^(file|gopher|dict|ftp|tftp|ldap|sftp):\/\//i;

      for (const str of strings) {
        if (dangerousProtocols.test(str)) {
          return {
            violation: true,
            ruleId: 'SEC-004',
            signature: 'Forbidden Protocol Scheme',
            culprit: str
          };
        }

        if (urlRegex.test(str)) {
          try {
            const parsed = new URL(str);
            const hostname = parsed.hostname.toLowerCase();

            // Loopback
            if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '0.0.0.0' || hostname.startsWith('127.')) {
              return {
                violation: true,
                ruleId: 'SEC-004',
                signature: 'SSRF: Loopback Address',
                culprit: hostname
              };
            }

            // Cloud Metadata endpoints
            if (hostname === '169.254.169.254' || hostname === 'metadata.google.internal' || hostname === '100.100.100.200') {
              return {
                violation: true,
                ruleId: 'SEC-004',
                signature: 'SSRF: Cloud Metadata Service Exfiltration Attempt',
                culprit: hostname
              };
            }

            // RFC 1918 Private Ranges
            if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
                /^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
                /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
              return {
                violation: true,
                ruleId: 'SEC-004',
                signature: 'SSRF: RFC 1918 Internal Network Access',
                culprit: hostname
              };
            }
          } catch {
            // Not a strict URL, skip
          }
        }
      }
      return { violation: false };
    }
  },

  PAYLOAD_BLAST_RADIUS: {
    id: 'SEC-005',
    name: 'Payload Blast Radius & DoS Guard',
    severity: 'MEDIUM',
    description: 'Enforces constraints on payload size, JSON depth, and key count to prevent parser exhaustion.',
    check: (params) => {
      const MAX_PAYLOAD_BYTES = 512 * 1024; // 512 KB
      const MAX_OBJECT_DEPTH = 12;
      const MAX_TOTAL_KEYS = 200;

      if (params === undefined || params === null) {
        return { violation: false };
      }

      let serialized;
      try {
        serialized = JSON.stringify(params);
      } catch (err) {
        return {
          violation: true,
          ruleId: 'SEC-005',
          signature: 'Unserializable / Circular Reference Payload Detected',
          culprit: err.message
        };
      }

      if (serialized && serialized.length > MAX_PAYLOAD_BYTES) {
        return {
          violation: true,
          ruleId: 'SEC-005',
          signature: `Payload Exceeds Limit (${Math.round(serialized.length / 1024)} KB > 512 KB)`,
          culprit: `Size: ${serialized.length} bytes`
        };
      }

      const depth = getObjectDepth(params);
      if (depth > MAX_OBJECT_DEPTH) {
        return {
          violation: true,
          ruleId: 'SEC-005',
          signature: `JSON Nesting Depth Exceeded (${depth} > ${MAX_OBJECT_DEPTH})`,
          culprit: `Depth: ${depth}`
        };
      }

      const allKeys = extractAllStrings(params);
      if (allKeys.length > MAX_TOTAL_KEYS) {
        return {
          violation: true,
          ruleId: 'SEC-005',
          signature: `Argument Element Count Exceeded (${allKeys.length} > ${MAX_TOTAL_KEYS})`,
          culprit: `Elements: ${allKeys.length}`
        };
      }

      return { violation: false };
    }
  }
};

module.exports = {
  calculateShannonEntropy,
  extractAllStrings,
  getObjectDepth,
  BUILTIN_RULES
};
