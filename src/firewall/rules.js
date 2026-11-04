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
      const traversalRegex = /(\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e\/|%252e%252e%252f|%252e%252e\/|%252e%252e%255c|\.\.;\/|\0|%00)/i;
      const sensitiveFiles = /([/\\]etc[/\\](passwd|shadow|hosts|sudoers)|[/\\]proc[/\\](self|\d+)|[/\\]sys[/\\]|[/\\]var[/\\]run[/\\]secrets|~?[/\\]\.(ssh|aws|gnupg|bash_history)|[c-z]:[/\\]windows[/\\]system32)/i;

      for (const str of strings) {
        if (str.includes('\0') || str.includes('%00')) {
          return {
            violation: true,
            ruleId: 'SEC-001',
            signature: 'Null Byte Path Poisoning / Extension Truncation',
            culprit: str.length > 80 ? str.slice(0, 77) + '...' : str
          };
        }
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
        /(?:[;&|]|\r?\n|\r)\s*(?:(?:(?:\/usr)?\/bin\/)?(?:rm|cat|bash|sh|zsh|dash|ksh|python|python3|perl|ruby|node|whoami|id|uname|hostname|env|printenv|sudo|chmod|chown|kill|pkill|find|curl|wget|nc|ncat|netcat|mkfifo|powershell))\b/i,
        /(&&\s*(?:(?:(?:\/usr)?\/bin\/)?(?:rm|cat|bash|sh|zsh|dash|ksh|python|python3|perl|ruby|node|whoami|id|uname|hostname|env|printenv|sudo|chmod|chown|kill|pkill|find|curl|wget|nc|ncat|netcat|mkfifo|powershell))\b)/i,
        /(\|\|\s*(?:(?:(?:\/usr)?\/bin\/)?(?:rm|cat|bash|sh|zsh|dash|ksh|python|python3|perl|ruby|node|whoami|id|uname|hostname|env|printenv|sudo|chmod|chown|kill|pkill|find|curl|wget|nc|ncat|netcat|mkfifo|powershell))\b)/i,
        /(\|\s*(?:(?:(?:\/usr)?\/bin\/)?(?:bash|sh|zsh|dash|ksh|curl|wget|nc|ncat|netcat|powershell|python|ruby))\b)/i,
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
        { name: 'Google API Key', regex: /\b(AIza[0-9A-Za-z-_]{35})\b/ },
        { name: 'Stripe Secret Key', regex: /\b([sr]k_(?:live|test)_[0-9a-zA-Z]{24,})\b/ },
        { name: 'Hugging Face Token', regex: /\b(hf_[a-zA-Z0-9]{34,})\b/ },
        { name: 'JSON Web Token (JWT)', regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/ },
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
      const dangerousProtocols = /(?:file|gopher|dict|ftp|tftp|ldap|sftp):\/\//i;

      for (const str of strings) {
        if (dangerousProtocols.test(str)) {
          return {
            violation: true,
            ruleId: 'SEC-004',
            signature: 'Forbidden Protocol Scheme',
            culprit: str.length > 80 ? str.slice(0, 77) + '...' : str
          };
        }

        if (urlRegex.test(str)) {
          try {
            const parsed = new URL(str.trim());
            const hostname = parsed.hostname.toLowerCase();

            // Loopback and unspecified addresses (IPv4 & IPv6 formats)
            if (
              hostname === 'localhost' ||
              hostname === '127.0.0.1' ||
              hostname === '[::1]' ||
              hostname === '0.0.0.0' ||
              hostname === '[::]' ||
              hostname === '[0:0:0:0:0:0:0:0]' ||
              hostname === '[0:0:0:0:0:0:0:1]' ||
              hostname.startsWith('127.') ||
              hostname.startsWith('[::ffff:7f') ||
              hostname.startsWith('[::ffff:127.')
            ) {
              return {
                violation: true,
                ruleId: 'SEC-004',
                signature: 'SSRF: Loopback Address',
                culprit: hostname
              };
            }

            // Cloud Metadata endpoints
            if (
              hostname === '169.254.169.254' ||
              hostname === '[::ffff:a9fe:a9fe]' ||
              hostname === '[::ffff:169.254.169.254]' ||
              hostname === 'metadata.google.internal' ||
              hostname === '100.100.100.200' ||
              hostname.startsWith('169.254.')
            ) {
              return {
                violation: true,
                ruleId: 'SEC-004',
                signature: 'SSRF: Cloud Metadata Service Exfiltration Attempt',
                culprit: hostname
              };
            }

            // RFC 1918 Private Ranges
            if (
              /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
              /^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
              /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
              hostname.startsWith('[::ffff:0a') ||
              hostname.startsWith('[::ffff:c0a8')
            ) {
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
  },

  PROMPT_INJECTION: {
    id: 'SEC-006',
    name: 'Prompt Injection & Instruction Hijacking Guard',
    severity: 'CRITICAL',
    description: 'Detects prompt injection, system instruction overrides, jailbreak phrases, and delimiter breaks in tool arguments.',
    check: (params) => {
      const strings = extractAllStrings(params);
      const injectionPatterns = [
        { name: 'Instruction Override', regex: /(?:ignore|disregard|forget|skip)\s+(?:all\s+)?(?:previous|prior|above|preceding)\s+(?:instructions|prompts|directives|rules)\b/i },
        { name: 'System Prompt Override', regex: /(?:system\s+prompt\s+override|override\s+system\s+instructions)\b/i },
        { name: 'Jailbreak / Developer Mode', regex: /(?:you\s+are\s+now\s+in\s+(?:developer|dan|unrestricted|god)\s+mode|do\s+anything\s+now\s+mode|jailbroken\s+mode)\b/i },
        { name: 'System Prompt Extraction', regex: /(?:reveal|print|display|dump)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions|internal\s+guidelines)\b/i },
        { name: 'Special LLM Delimiter Breakout', regex: /(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[\/INST\]|<<SYS>>|<\/s>|<start_of_turn>|<end_of_turn>)/i }
      ];

      for (const str of strings) {
        for (const { name, regex } of injectionPatterns) {
          if (regex.test(str)) {
            return {
              violation: true,
              ruleId: 'SEC-006',
              signature: `Prompt Injection: ${name}`,
              culprit: str.length > 80 ? str.slice(0, 77) + '...' : str
            };
          }
        }
      }
      return { violation: false };
    }
  },

  SQL_INJECTION: {
    id: 'SEC-007',
    name: 'SQL & Query Injection Guard',
    severity: 'HIGH',
    description: 'Detects SQL injection signatures, union extraction, boolean-based bypasses, and unauthorized DDL/DML queries.',
    check: (params) => {
      const strings = extractAllStrings(params);
      const sqlPatterns = [
        { name: 'Union-based Extraction', regex: /(\b(?:UNION\s+(?:ALL\s+)?SELECT)\b)/i },
        { name: 'Boolean Bypass', regex: /(?:'\s*(?:OR|AND)\s*'?\w+'?\s*=\s*'?\w+'?|\b(?:OR|AND)\s+(?:1=1|true=true))/i },
        { name: 'Destructive DDL/DML', regex: /(\b(?:DROP|TRUNCATE|ALTER)\s+(?:TABLE|DATABASE|VIEW)\b|\bDELETE\s+FROM\b|\bUPDATE\s+\w+\s+SET\b|\bINSERT\s+INTO\b)/i },
        { name: 'Stored Procedure Exec', regex: /(\b(?:EXEC|EXECUTE)\s*(?:\(|\s+)(?:@|xp_|sp_))/i },
        { name: 'Time-Based Blind Injection', regex: /(\bSLEEP\s*\(\s*\d+\s*\)|\bBENCHMARK\s*\(\s*\d+|\bpg_sleep\s*\(\s*\d+\s*\)|\bWAITFOR\s+DELAY\s+'[^']+')/i }
      ];

      for (const str of strings) {
        for (const { name, regex } of sqlPatterns) {
          if (regex.test(str)) {
            return {
              violation: true,
              ruleId: 'SEC-007',
              signature: `SQL Injection: ${name}`,
              culprit: str.length > 80 ? str.slice(0, 77) + '...' : str
            };
          }
        }
      }
      return { violation: false };
    }
  },

  PROTOTYPE_POLLUTION: {
    id: 'SEC-008',
    name: 'Prototype Pollution & Object Injection Guard',
    severity: 'HIGH',
    description: 'Detects __proto__, constructor.prototype, and prototype override vectors in input objects.',
    check: (params) => {
      // 1. Check for altered prototype on input object
      if (params && typeof params === 'object') {
        const proto = Object.getPrototypeOf(params);
        if (proto && proto !== Object.prototype && proto !== Array.prototype) {
          return {
            violation: true,
            ruleId: 'SEC-008',
            signature: 'Prototype Pollution: Altered Object Prototype',
            culprit: '__proto__'
          };
        }
      }

      // 2. Deep recursive check for structured prototype pollution keys
      function hasStructuredPollution(obj, depth = 0, visited = new Set()) {
        if (!obj || typeof obj !== 'object' || depth > 10 || visited.has(obj)) return false;
        visited.add(obj);

        const keys = Object.getOwnPropertyNames(obj);
        if (keys.includes('__proto__')) return true;

        if (keys.includes('constructor') && obj.constructor && typeof obj.constructor === 'object') {
          if (Object.getOwnPropertyNames(obj.constructor).includes('prototype')) return true;
        }

        for (const k of keys) {
          const val = obj[k];
          if (val && typeof val === 'object') {
            if (k === 'constructor' && (Object.prototype.hasOwnProperty.call(val, 'prototype') || Object.getOwnPropertyNames(val).includes('prototype'))) {
              return true;
            }
            if (k === '__proto__') {
              return true;
            }
            if (hasStructuredPollution(val, depth + 1, visited)) {
              return true;
            }
          }
        }
        return false;
      }

      if (hasStructuredPollution(params)) {
        return {
          violation: true,
          ruleId: 'SEC-008',
          signature: 'Prototype Pollution: Structured Object Injection Detected',
          culprit: 'constructor.prototype / __proto__'
        };
      }

      // 3. Traversal for string keys and values
      const strings = extractAllStrings(params);
      const pollutionRegex = /(\b__proto__\b|\bconstructor\.prototype\b|\bprototype\.constructor\b)/i;

      for (const str of strings) {
        if (pollutionRegex.test(str)) {
          return {
            violation: true,
            ruleId: 'SEC-008',
            signature: 'Prototype Pollution Key/Vector Detected',
            culprit: str
          };
        }
      }
      return { violation: false };
    }
  },

  ENV_SECRETS_EXFILTRATION: {
    id: 'SEC-009',
    name: 'Environment & Critical Secrets Exfiltration Guard',
    severity: 'HIGH',
    description: 'Detects access attempts targeting .env files, private keys, cloud tokens, kubeconfig, and credentials stores.',
    check: (params) => {
      const strings = extractAllStrings(params);
      const sensitiveFiles = [
        { name: 'Environment Configuration File', regex: /(\.env(\.(?:local|prod|production|dev|development|test|staging))?)\b/i },
        { name: 'Cloud Credentials Store', regex: /([/\\]\.aws[/\\](?:credentials|config)|[/\\]\.azure[/\\]|[/\\]\.gcloud[/\\]|^\.aws[/\\](?:credentials|config)|^\.azure[/\\]|^\.gcloud[/\\])/i },
        { name: 'SSH Private Key Identity', regex: /(\b(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)(?:\.pub)?)\b/i },
        { name: 'Kubernetes or Docker Config', regex: /([/\\]\.kube[/\\]config|[/\\]\.docker[/\\]config\.json|^\.kube[/\\]config|^\.docker[/\\]config\.json)\b/i },
        { name: 'Cloud Service Account Key', regex: /(\b(?:service[-_]?account|gcp[-_]creds|firebase[-_]adminsdk).*\.json)\b/i },
        { name: 'System Secrets File', regex: /([/\\]etc[/\\](?:environment|security[/\\]limits\.conf|shadow))\b/i }
      ];

      for (const str of strings) {
        for (const { name, regex } of sensitiveFiles) {
          if (regex.test(str)) {
            return {
              violation: true,
              ruleId: 'SEC-009',
              signature: `Secrets Exfiltration: ${name}`,
              culprit: str.length > 80 ? str.slice(0, 77) + '...' : str
            };
          }
        }
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
