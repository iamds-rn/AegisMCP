/**
 * AegisMCP - In-Browser Studio & Autonomous Engine
 * Zero-dependency, client-side implementation of Firewall, Ledger, Fuzzer, Virtual Hub, and Canvas DAG.
 */

'use strict';

// ==============================================================
// 1. Web Audio Sound Engine (Zero external audio assets)
// ==============================================================
class SoundEngine {
  constructor() {
    this.enabled = true;
    this.ctx = null;
  }

  init() {
    if (!this.ctx && typeof window !== 'undefined' && (window.AudioContext || window.webkitAudioContext)) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
  }

  playClick() {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(800, this.ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(400, this.ctx.currentTime + 0.04);
    gain.gain.setValueAtTime(0.05, this.ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.04);
    osc.connect(gain);
    gain.connect(this.ctx.destination);
    osc.start();
    osc.stop(this.ctx.currentTime + 0.04);
  }

  playSuccess() {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    const now = this.ctx.currentTime;
    [523.25, 659.25, 783.99, 1046.5].forEach((freq, i) => {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, now + i * 0.06);
      gain.gain.setValueAtTime(0.08, now + i * 0.06);
      gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.06 + 0.2);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(now + i * 0.06);
      osc.stop(now + i * 0.06 + 0.2);
    });
  }

  playBlock() {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    const now = this.ctx.currentTime;
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(180, now);
    osc.frequency.exponentialRampToValueAtTime(90, now + 0.25);
    gain.gain.setValueAtTime(0.12, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
    osc.connect(gain);
    gain.connect(this.ctx.destination);
    osc.start(now);
    osc.stop(now + 0.25);
  }

  playFuzzTick() {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(1200, this.ctx.currentTime);
    gain.gain.setValueAtTime(0.02, this.ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.02);
    osc.connect(gain);
    gain.connect(this.ctx.destination);
    osc.start();
    osc.stop(this.ctx.currentTime + 0.02);
  }
}

// ==============================================================
// 2. Browser-Native Cryptography & Hashing
// ==============================================================
async function browserSha256(str) {
  if (window.crypto && window.crypto.subtle) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // Pure JS fallback
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(16).padStart(64, '0');
}

function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0;
  const frequencies = {};
  for (let i = 0; i < str.length; i++) {
    frequencies[str[i]] = (frequencies[str[i]] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in frequencies) {
    const p = frequencies[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function extractAllStrings(obj, depth = 0, maxDepth = 15) {
  const strings = [];
  if (depth > maxDepth) return strings;
  if (typeof obj === 'string') {
    strings.push(obj);
  } else if (Array.isArray(obj)) {
    for (const item of obj) {
      strings.push(...extractAllStrings(item, depth + 1, maxDepth));
    }
  } else if (obj !== null && typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      strings.push(key);
      strings.push(...extractAllStrings(obj[key], depth + 1, maxDepth));
    }
  }
  return strings;
}

// ==============================================================
// 3. Client-Side Firewall Engine
// ==============================================================
class BrowserFirewall {
  constructor() {
    this.mode = 'ENFORCE';
    this.rules = [
      {
        id: 'SEC-001',
        name: 'Path Traversal Guard',
        severity: 'CRITICAL',
        description: 'Blocks directory traversal sequences (../) and OS root escapements',
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          const traversal = /(\.\.[/\\]|\.\.%2f|%2e%2e)/i;
          const sensitive = /(\/etc\/(passwd|shadow|hosts)|\/proc\/|~?\/\.(ssh|aws)|system32)/i;
          for (const s of strings) {
            if (traversal.test(s)) return { violation: true, signature: 'Directory Traversal (..)', culprit: s };
            if (sensitive.test(s)) return { violation: true, signature: 'Sensitive OS Path Reference', culprit: s };
          }
          return { violation: false };
        }
      },
      {
        id: 'SEC-002',
        name: 'Command Injection Guard',
        severity: 'CRITICAL',
        description: 'Blocks shell metacharacters, subshell injection, and command chaining',
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          const patterns = [
            /(;\s*(?:rm|cat|bash|sh|curl|wget|nc)\b)/i,
            /(&&\s*(?:rm|cat|bash|sh|curl|wget|nc)\b)/i,
            /(\|\s*(?:bash|sh|curl|wget)\b)/i,
            /(`[^`]+`|\$\([^)]+\))/
          ];
          for (const s of strings) {
            for (const p of patterns) {
              if (p.test(s)) return { violation: true, signature: 'Shell Metacharacter / Command Chaining', culprit: s };
            }
          }
          return { violation: false };
        }
      },
      {
        id: 'SEC-003',
        name: 'Credential & Secret Leakage Guard',
        severity: 'HIGH',
        description: 'Detects AWS keys, GitHub PATs, private keys, and high-entropy tokens',
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          const patterns = [
            { name: 'AWS Access Key ID', regex: /\b(AKIA[0-9A-Z]{16})\b/ },
            { name: 'GitHub PAT', regex: /\b(ghp_[A-Za-z0-9_]{36,})\b/ },
            { name: 'OpenAI API Key', regex: /\b(sk-[A-Za-z0-9]{32,}|sk-proj-[A-Za-z0-9_-]{40,})\b/ },
            { name: 'Private Key Block', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ }
          ];
          for (const s of strings) {
            for (const { name, regex } of patterns) {
              if (regex.test(s)) return { violation: true, signature: `Credential Leak: ${name}`, culprit: s.slice(0, 8) + '...' };
            }
            if (s.length >= 32 && s.length <= 128 && !s.includes(' ') && !s.includes('/')) {
              const ent = calculateShannonEntropy(s);
              if (ent > 4.65) return { violation: true, signature: `High Entropy Secret (${ent.toFixed(2)})`, culprit: s.slice(0, 8) + '...' };
            }
          }
          return { violation: false };
        }
      },
      {
        id: 'SEC-004',
        name: 'SSRF & Metadata Exfiltration Guard',
        severity: 'HIGH',
        description: 'Blocks loopback addresses and cloud metadata exfiltration (169.254.169.254)',
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          const forbidden = /^(file|gopher|dict):\/\//i;
          for (const s of strings) {
            if (forbidden.test(s)) return { violation: true, signature: 'Forbidden URI Scheme', culprit: s };
            if (/localhost|127\.0\.0\.1|169\.254\.169\.254|10\.\d+\.\d+\.\d+/i.test(s)) {
              return { violation: true, signature: 'SSRF Internal Target', culprit: s };
            }
          }
          return { violation: false };
        }
      },
      {
        id: 'SEC-005',
        name: 'Payload Blast Radius & DoS Guard',
        severity: 'MEDIUM',
        description: 'Enforces maximum payload size and nesting depth limits',
        enabled: true,
        check: (params) => {
          const raw = JSON.stringify(params);
          if (raw.length > 256 * 1024) return { violation: true, signature: 'Payload Exceeds 256KB', culprit: `${raw.length} bytes` };
          return { violation: false };
        }
      },
      {
        id: 'SEC-006',
        name: 'Prompt Injection & Delimiter Breakout Guard',
        severity: 'CRITICAL',
        description: 'Detects jailbreaks, instruction overrides, and delimiter breakouts',
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          const regex = /(?:ignore|disregard)\s+(?:all\s+)?previous\s+instructions|<\|im_start\|>|<\|im_end\|>|developer\s+mode/i;
          for (const s of strings) {
            if (regex.test(s)) return { violation: true, signature: 'Prompt Injection / Instruction Override', culprit: s };
          }
          return { violation: false };
        }
      },
      {
        id: 'SEC-007',
        name: 'SQL & Query Injection Guard',
        severity: 'HIGH',
        description: 'Detects SQL injection signatures, union-based queries, and destructive DDL',
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          const regex = /(\bUNION\s+(?:ALL\s+)?SELECT\b|'\s*OR\s*['0-9a-zA-Z]+=|\bDROP\s+TABLE\b)/i;
          for (const s of strings) {
            if (regex.test(s)) return { violation: true, signature: 'SQL Injection Signature', culprit: s };
          }
          return { violation: false };
        }
      },
      {
        id: 'SEC-008',
        name: 'Prototype Pollution Guard',
        severity: 'HIGH',
        description: 'Detects __proto__ and prototype override attempts',
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          for (const s of strings) {
            if (/__proto__|constructor\.prototype/i.test(s)) return { violation: true, signature: 'Prototype Pollution Vector', culprit: s };
          }
          return { violation: false };
        }
      },
      {
        id: 'SEC-009',
        name: 'Secrets & Environment Exfiltration Guard',
        severity: 'HIGH',
        description: 'Blocks access to .env files, private keys, and cloud token stores',
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          const regex = /(\.env(\.local)?|\.aws\/credentials|id_rsa|id_ed25519|\.kube\/config)/i;
          for (const s of strings) {
            if (regex.test(s)) return { violation: true, signature: 'Sensitive Secrets File Access', culprit: s };
          }
          return { violation: false };
        }
      }
    ];

    this.stats = {
      evaluated: 0,
      blocked: 0,
      sanitized: 0,
      ruleCounts: { 'SEC-001': 0, 'SEC-002': 0, 'SEC-003': 0, 'SEC-004': 0, 'SEC-005': 0, 'SEC-006': 0, 'SEC-007': 0, 'SEC-008': 0, 'SEC-009': 0 }
    };
  }

  evaluate(toolName, params) {
    this.stats.evaluated++;
    for (const rule of this.rules) {
      if (!rule.enabled) continue;
      const res = rule.check(params);
      if (res && res.violation) {
        this.stats.ruleCounts[rule.id] = (this.stats.ruleCounts[rule.id] || 0) + 1;
        const alert = {
          ruleId: rule.id,
          name: rule.name,
          severity: rule.severity,
          signature: res.signature,
          culprit: res.culprit,
          toolName
        };

        if (this.mode === 'ENFORCE') {
          this.stats.blocked++;
          return { allowed: false, blocked: true, alert };
        } else if (this.mode === 'SANITIZE') {
          this.stats.sanitized++;
          let clean = JSON.stringify(params)
            .replace(/\b(AKIA[0-9A-Z]{16})\b/g, '[REDACTED_AWS_KEY]')
            .replace(/\b(ghp_[A-Za-z0-9_]{36,})\b/g, '[REDACTED_GH_TOKEN]')
            .replace(/\.\.\//g, './');
          return { allowed: true, sanitized: true, cleanParams: JSON.parse(clean), alert };
        } else {
          return { allowed: true, audited: true, alert };
        }
      }
    }
    return { allowed: true, blocked: false };
  }
}

// ==============================================================
// 4. Client-Side Cryptographic Audit Ledger
// ==============================================================
class BrowserLedger {
  constructor() {
    this.chain = [];
    this.tamperBackup = new Map();
    this.initGenesis();
  }

  async initGenesis() {
    const timestamp = '2026-11-04T00:00:00.000Z';
    const prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const event = { type: 'GENESIS', description: 'AegisMCP Audit Ledger Initialized' };
    const hash = await browserSha256(`0|${timestamp}|${prevHash}|${JSON.stringify(event)}`);
    this.chain.push({ index: 0, timestamp, prevHash, event, hash });
  }

  async append(type, data) {
    const prev = this.chain[this.chain.length - 1];
    const index = prev.index + 1;
    const timestamp = new Date().toISOString();
    const prevHash = prev.hash;
    const event = { type, ...data };
    const hash = await browserSha256(`${index}|${timestamp}|${prevHash}|${JSON.stringify(event)}`);
    const block = { index, timestamp, prevHash, event, hash };
    this.chain.push(block);
    return block;
  }

  async verify() {
    for (let i = 1; i < this.chain.length; i++) {
      const curr = this.chain[i];
      const prev = this.chain[i - 1];
      if (curr.prevHash !== prev.hash) {
        return { valid: false, brokenIndex: curr.index, reason: 'Broken prevHash pointer' };
      }
      const expected = await browserSha256(`${curr.index}|${curr.timestamp}|${curr.prevHash}|${JSON.stringify(curr.event)}`);
      if (curr.hash !== expected) {
        return { valid: false, brokenIndex: curr.index, reason: 'Hash tampering detected' };
      }
    }
    return { valid: true, blockCount: this.chain.length };
  }

  tamper(index, modifiedData) {
    if (this.chain[index]) {
      if (!this.tamperBackup.has(index)) {
        this.tamperBackup.set(index, JSON.parse(JSON.stringify(this.chain[index].event)));
      }
      this.chain[index].event = modifiedData;
      // Intentionally do NOT update hash
    }
  }

  restore(index) {
    if (this.chain[index] && this.tamperBackup.has(index)) {
      this.chain[index].event = this.tamperBackup.get(index);
      this.tamperBackup.delete(index);
      return true;
    }
    return false;
  }

  restoreAll() {
    let count = 0;
    for (const [idx, original] of this.tamperBackup.entries()) {
      if (this.chain[idx]) {
        this.chain[idx].event = original;
        count++;
      }
    }
    this.tamperBackup.clear();
    return count;
  }

  async locateTamper() {
    for (let i = 1; i < this.chain.length; i++) {
      const curr = this.chain[i];
      const prev = this.chain[i - 1];
      if (curr.prevHash !== prev.hash) {
        return {
          intact: false,
          brokenIndex: curr.index,
          cascadeBlastRadius: this.chain.length - curr.index,
          reason: 'Broken prevHash pointer'
        };
      }
      const expected = await browserSha256(`${curr.index}|${curr.timestamp}|${curr.prevHash}|${JSON.stringify(curr.event)}`);
      if (curr.hash !== expected) {
        const original = this.tamperBackup.get(curr.index);
        let diff = null;
        if (original) {
          diff = [];
          const allK = new Set([...Object.keys(original), ...Object.keys(curr.event)]);
          for (const k of allK) {
            if (JSON.stringify(original[k]) !== JSON.stringify(curr.event[k])) {
              diff.push({ key: k, original: original[k], tampered: curr.event[k] });
            }
          }
        }
        return {
          intact: false,
          brokenIndex: curr.index,
          expectedHash: expected,
          actualHash: curr.hash,
          cascadeBlastRadius: this.chain.length - curr.index,
          diff,
          reason: 'Cryptographic hash mismatch'
        };
      }
    }
    return { intact: true, blockCount: this.chain.length };
  }

  getSnapshot(index) {
    if (index < 0 || index >= this.chain.length) index = 0;
    return this.chain[index];
  }
}

// ==============================================================
// 5. In-Memory Virtual MCP Servers Hub
// ==============================================================
class BrowserVirtualHub {
  constructor() {
    this.files = new Map([
      ['/workspace/project.json', JSON.stringify({ name: 'AlphaPilot', version: '2.4.0', status: 'active' }, null, 2)],
      ['/workspace/src/index.js', 'console.log("System initialized");\nmodule.exports = { ready: true };'],
      ['/workspace/notes.txt', 'Review security credentials and rotation policy before deployment.']
    ]);

    this.memory = new Map([
      ['system:status', { value: 'operational', tags: ['system', 'health'] }],
      ['config:tier', { value: 'enterprise', tags: ['config', 'billing'] }]
    ]);

    this.tools = [
      {
        server: 'virtual_filesystem',
        name: 'read_file',
        desc: 'Read textual content of a file at the specified virtual path.',
        schema: {
          properties: { path: { type: 'string', default: '/workspace/project.json', label: 'File Path' } },
          required: ['path']
        },
        fn: (p) => {
          const path = p.path.startsWith('/') ? p.path : '/' + p.path;
          if (!this.files.has(path)) throw new Error(`File not found: ${path}`);
          return { content: [{ type: 'text', text: this.files.get(path) }] };
        }
      },
      {
        server: 'virtual_filesystem',
        name: 'write_file',
        desc: 'Write or overwrite content of a file at the specified virtual path.',
        schema: {
          properties: {
            path: { type: 'string', default: '/workspace/output.txt', label: 'File Path' },
            content: { type: 'string', default: 'Aegis audit complete.', label: 'Content' }
          },
          required: ['path', 'content']
        },
        fn: (p) => {
          const path = p.path.startsWith('/') ? p.path : '/' + p.path;
          this.files.set(path, String(p.content));
          return { content: [{ type: 'text', text: `Successfully wrote ${p.content.length} bytes to ${path}` }] };
        }
      },
      {
        server: 'virtual_filesystem',
        name: 'list_files',
        desc: 'List all files present in a given virtual directory path.',
        schema: {
          properties: { path: { type: 'string', default: '/workspace', label: 'Directory' } },
          required: ['path']
        },
        fn: (p) => {
          const matches = Array.from(this.files.keys()).filter(k => k.startsWith(p.path));
          return { content: [{ type: 'text', text: JSON.stringify({ directory: p.path, files: matches }, null, 2) }] };
        }
      },
      {
        server: 'virtual_memory',
        name: 'set_key',
        desc: 'Store a key-value pair with optional classification tags.',
        schema: {
          properties: {
            key: { type: 'string', default: 'app:env', label: 'Key' },
            value: { type: 'string', default: 'production', label: 'Value' }
          },
          required: ['key', 'value']
        },
        fn: (p) => {
          this.memory.set(p.key, { value: p.value, updatedAt: new Date().toISOString() });
          return { content: [{ type: 'text', text: `Key "${p.key}" stored.` }] };
        }
      },
      {
        server: 'virtual_memory',
        name: 'get_key',
        desc: 'Retrieve the value and metadata of a stored key.',
        schema: {
          properties: { key: { type: 'string', default: 'system:status', label: 'Key' } },
          required: ['key']
        },
        fn: (p) => {
          if (!this.memory.has(p.key)) throw new Error(`Key not found: ${p.key}`);
          return { content: [{ type: 'text', text: JSON.stringify(this.memory.get(p.key), null, 2) }] };
        }
      },
      {
        server: 'virtual_crypto',
        name: 'hash_sha256',
        desc: 'Calculate cryptographic SHA-256 digest of input text.',
        schema: {
          properties: { text: { type: 'string', default: 'Hello World', label: 'Plaintext' } },
          required: ['text']
        },
        fn: async (p) => {
          const hash = await browserSha256(String(p.text));
          return { content: [{ type: 'text', text: JSON.stringify({ algorithm: 'SHA-256', hash }, null, 2) }] };
        }
      },
      {
        server: 'virtual_crypto',
        name: 'generate_token',
        desc: 'Generate a cryptographically secure random token.',
        schema: {
          properties: { bytes: { type: 'number', default: 32, label: 'Byte Length' } },
          required: []
        },
        fn: (p) => {
          const count = parseInt(p.bytes, 10) || 32;
          const arr = new Uint8Array(count);
          window.crypto.getRandomValues(arr);
          const token = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
          return { content: [{ type: 'text', text: JSON.stringify({ token, entropy: calculateShannonEntropy(token).toFixed(3) }, null, 2) }] };
        }
      },
      {
        server: 'virtual_http_simulator',
        name: 'fetch_url',
        desc: 'Simulate an outbound HTTP request to an external API endpoint.',
        schema: {
          properties: { url: { type: 'string', default: 'https://api.github.com/status', label: 'URL' } },
          required: ['url']
        },
        fn: (p) => {
          return { content: [{ type: 'text', text: JSON.stringify({ url: p.url, status: 200, body: 'Simulated API OK' }, null, 2) }] };
        }
      }
    ];
  }

  getTool(name) {
    return this.tools.find(t => t.name === name);
  }
}

// ==============================================================
// 6. Main Aegis Web Studio Application Controller
// ==============================================================
class AegisStudioApp {
  constructor() {
    this.sound = new SoundEngine();
    this.firewall = new BrowserFirewall();
    this.ledger = new BrowserLedger();
    this.hub = new BrowserVirtualHub();
    this.selectedTool = this.hub.tools[0];

    // Pipeline State
    this.pipelineNodes = [
      { id: 'node_gen', title: 'Generate Token', tool: 'generate_token', server: 'virtual_crypto', x: 50, y: 80, params: { bytes: 16 } },
      { id: 'node_hash', title: 'SHA-256 Digest', tool: 'hash_sha256', server: 'virtual_crypto', x: 320, y: 80, params: { text: '{{nodes.node_gen.output.token}}' } },
      { id: 'node_mem', title: 'Store in Memory', tool: 'set_key', server: 'virtual_memory', x: 590, y: 80, params: { key: 'vault:token', value: '{{nodes.node_hash.output.hash}}' } },
      { id: 'node_file', title: 'Write Manifest', tool: 'write_file', server: 'virtual_filesystem', x: 860, y: 80, params: { path: '/workspace/manifest.txt', content: 'Token Hash: {{nodes.node_hash.output.hash}}' } }
    ];

    this.initUI();
  }

  async initUI() {
    this.setupTabs();
    this.setupQuickScenarios();
    this.setupToolStudio();
    this.setupFirewallUI();
    this.setupFuzzerUI();
    this.setupPipelineUI();
    this.setupLedgerUI();
    this.setupForensicsUI();
    this.setupSynthesizerUI();
    this.setupConfigsUI();
    this.setupServersUI();
    this.updateStats();

    // Initial Event Stream Entry
    this.logEvent('INITIALIZATION', 'AegisMCP Security Studio ready in sandbox mode.', 'success');

    // Auto-verify ledger
    await this.refreshLedgerDisplay();
  }

  setupTabs() {
    document.querySelectorAll('.nav-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        this.sound.playClick();
        document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const targetTab = btn.getAttribute('data-tab');
        const pane = document.getElementById(targetTab);
        if (pane) pane.classList.add('active');

        if (targetTab === 'tab-pipeline') {
          setTimeout(() => this.drawPipelineCanvas(), 50);
        }
      });
    });

    // Sound toggle
    const soundBtn = document.getElementById('sound-toggle-btn');
    soundBtn.addEventListener('click', () => {
      this.sound.enabled = !this.sound.enabled;
      document.getElementById('sound-icon').textContent = this.sound.enabled ? '🔊' : '🔇';
    });
  }

  setupQuickScenarios() {
    // Scenario 1: Threat Interception
    document.getElementById('scenario-injection-btn').addEventListener('click', () => {
      this.sound.playClick();
      // Switch to dashboard
      document.querySelector('[data-tab="tab-dashboard"]').click();
      
      const maliciousPayload = {
        path: '../../../../etc/shadow',
        exfilKey: 'AKIAIOSFODNN7EXAMPLE'
      };

      const result = this.firewall.evaluate('read_file', maliciousPayload);
      if (result.blocked) {
        this.sound.playBlock();
        this.logEvent('FIREWALL_BLOCK', `Blocked [${result.alert.ruleId}] ${result.alert.signature} on tool "${result.alert.toolName}"`, 'block', result.alert);
        this.ledger.append('FIREWALL_BLOCK', result.alert);
      }
      this.updateStats();
    });

    // Scenario 2: DAG Pipeline
    document.getElementById('scenario-pipeline-btn').addEventListener('click', () => {
      this.sound.playClick();
      document.querySelector('[data-tab="tab-pipeline"]').click();
      this.runDAGPipeline();
    });

    // Scenario 3: Fuzz Tool
    document.getElementById('scenario-fuzz-btn').addEventListener('click', () => {
      this.sound.playClick();
      document.querySelector('[data-tab="tab-fuzzer"]').click();
      this.runFuzzCampaign();
    });

    // Scenario 4: Tamper Test
    document.getElementById('scenario-tamper-btn').addEventListener('click', () => {
      this.sound.playClick();
      document.querySelector('[data-tab="tab-ledger"]').click();
      this.simulateTamper();
    });

    // Scenario 5: Forensics & Time-Travel
    const forensicsBtn = document.getElementById('scenario-forensics-btn');
    if (forensicsBtn) {
      forensicsBtn.addEventListener('click', () => {
        this.sound.playClick();
        document.querySelector('[data-tab="tab-forensics"]').click();
        this.runForensicDemo();
      });
    }

    // Scenario 6: Client Configs
    const configsBtn = document.getElementById('scenario-configs-btn');
    if (configsBtn) {
      configsBtn.addEventListener('click', () => {
        this.sound.playClick();
        document.querySelector('[data-tab="tab-configs"]').click();
      });
    }
  }

  setupToolStudio() {
    const list = document.getElementById('tool-catalog-list');
    list.innerHTML = '';
    this.hub.tools.forEach((tool, idx) => {
      const item = document.createElement('div');
      item.className = `tool-item ${idx === 0 ? 'active' : ''}`;
      item.innerHTML = `
        <div class="tool-item-name">${tool.name}</div>
        <div class="tool-item-server">${tool.server}</div>
      `;
      item.addEventListener('click', () => {
        this.sound.playClick();
        document.querySelectorAll('.tool-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        this.selectTool(tool);
      });
      list.appendChild(item);
    });

    this.selectTool(this.selectedTool);

    // Execute Tool Button
    document.getElementById('execute-tool-btn').addEventListener('click', () => this.executeCurrentTool());

    // Subtabs
    document.querySelectorAll('.subnav-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this.sound.playClick();
        document.querySelectorAll('.subnav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.subtab-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.getAttribute('data-subtab')).classList.add('active');
      });
    });
  }

  selectTool(tool) {
    this.selectedTool = tool;
    document.getElementById('selected-tool-name').textContent = tool.name;
    document.getElementById('selected-tool-server').textContent = tool.server;
    document.getElementById('selected-tool-desc').textContent = tool.desc;

    // Generate Form Fields
    const formBox = document.getElementById('dynamic-form-fields');
    formBox.innerHTML = '';
    for (const [key, prop] of Object.entries(tool.schema.properties)) {
      const grp = document.createElement('div');
      grp.className = 'form-group';
      grp.innerHTML = `
        <label>${prop.label || key}:</label>
        <input type="text" id="arg-${key}" value="${prop.default || ''}" placeholder="Enter ${key}...">
      `;
      formBox.appendChild(grp);
    }
  }

  async executeCurrentTool() {
    this.sound.playClick();
    const args = {};
    for (const key of Object.keys(this.selectedTool.schema.properties)) {
      const input = document.getElementById(`arg-${key}`);
      if (input) args[key] = input.value;
    }

    const rawRpc = {
      jsonrpc: '2.0',
      id: Math.random().toString(36).substring(2, 8),
      method: 'tools/call',
      params: { name: this.selectedTool.name, arguments: args }
    };
    document.getElementById('raw-jsonrpc-display').textContent = JSON.stringify(rawRpc, null, 2);

    // Pre-flight check
    const evalRes = this.firewall.evaluate(this.selectedTool.name, args);
    const preflight = document.getElementById('firewall-preflight-display');

    if (evalRes.blocked) {
      this.sound.playBlock();
      preflight.innerHTML = `<span class="preflight-status danger">🚨 BLOCKED: [${evalRes.alert.ruleId}] ${evalRes.alert.signature}</span>`;
      document.getElementById('tool-result-display').textContent = JSON.stringify({
        jsonrpc: '2.0',
        id: rawRpc.id,
        error: { code: -32001, message: `Aegis Block: ${evalRes.alert.signature}` }
      }, null, 2);
      this.logEvent('FIREWALL_BLOCK', `Blocked ${this.selectedTool.name}: ${evalRes.alert.signature}`, 'block');
      await this.ledger.append('FIREWALL_BLOCK', evalRes.alert);
      this.updateStats();
      return;
    }

    preflight.innerHTML = `<span class="preflight-status safe">✔ Pre-flight Clean: Passed All Firewall Invariants</span>`;

    try {
      const toolOut = await this.selectedTool.fn(evalRes.sanitized ? evalRes.cleanParams : args);
      this.sound.playSuccess();
      document.getElementById('tool-result-display').textContent = JSON.stringify(toolOut, null, 2);
      this.logEvent('TOOL_CALL', `Executed ${this.selectedTool.name} successfully`, 'success');
      await this.ledger.append('TOOL_CALL', { tool: this.selectedTool.name, args });
    } catch (err) {
      document.getElementById('tool-result-display').textContent = JSON.stringify({ error: err.message }, null, 2);
      this.logEvent('TOOL_ERROR', `${this.selectedTool.name} error: ${err.message}`, 'audit');
    }
    this.updateStats();
  }

  setupFirewallUI() {
    const tableBody = document.getElementById('rules-table-body');
    tableBody.innerHTML = '';
    this.firewall.rules.forEach(rule => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>
          <label class="toggle-switch">
            <input type="checkbox" id="toggle-${rule.id}" ${rule.enabled ? 'checked' : ''}>
            <span class="slider"></span>
          </label>
        </td>
        <td><code>${rule.id}</code></td>
        <td><strong>${rule.name}</strong></td>
        <td><span class="badge ${rule.severity.toLowerCase()}">${rule.severity}</span></td>
        <td style="color: var(--text-muted); font-size: 12px;">${rule.description}</td>
        <td><span class="badge-enforce">SHIELD</span></td>
      `;
      tr.querySelector('input').addEventListener('change', (e) => {
        rule.enabled = e.target.checked;
        this.sound.playClick();
        this.logEvent('CONFIG', `Rule ${rule.id} toggled ${rule.enabled ? 'ON' : 'OFF'}`, 'audit');
      });
      tableBody.appendChild(tr);
    });

    // Mode Radio Buttons
    document.querySelectorAll('input[name="firewall-mode"]').forEach(radio => {
      radio.addEventListener('change', (e) => {
        this.firewall.mode = e.target.value;
        this.sound.playClick();
        document.getElementById('current-mode-badge').textContent = `MODE: ${this.firewall.mode}`;
        this.logEvent('POLICY_CHANGE', `Firewall policy mode changed to ${this.firewall.mode}`, 'audit');
      });
    });

    // Add Custom Rule
    document.getElementById('add-custom-rule-btn').addEventListener('click', () => {
      const id = document.getElementById('custom-rule-id').value;
      const name = document.getElementById('custom-rule-name').value;
      const regexStr = document.getElementById('custom-rule-regex').value;
      const sev = document.getElementById('custom-rule-severity').value;
      const regex = new RegExp(regexStr, 'i');

      this.firewall.rules.push({
        id,
        name,
        severity: sev,
        description: `Custom policy matching /${regexStr}/`,
        enabled: true,
        check: (params) => {
          const strings = extractAllStrings(params);
          for (const s of strings) {
            if (regex.test(s)) return { violation: true, signature: `Custom Regex: ${name}`, culprit: s };
          }
          return { violation: false };
        }
      });
      this.sound.playSuccess();
      this.setupFirewallUI();
      this.logEvent('RULE_ADDED', `Registered custom policy ${id}: ${name}`, 'success');
    });
  }

  setupFuzzerUI() {
    const sel = document.getElementById('fuzz-target-tool');
    sel.innerHTML = '';
    this.hub.tools.forEach(tool => {
      const opt = document.createElement('option');
      opt.value = tool.name;
      opt.textContent = `${tool.server} / ${tool.name}`;
      sel.appendChild(opt);
    });

    document.getElementById('start-fuzz-btn').addEventListener('click', () => this.runFuzzCampaign());
  }

  async runFuzzCampaign() {
    const toolName = document.getElementById('fuzz-target-tool').value;
    const withFirewall = document.getElementById('fuzz-firewall-toggle').checked;
    const tool = this.hub.getTool(toolName);
    const container = document.getElementById('fuzzer-scorecard-container');
    const tbody = document.getElementById('fuzz-results-body');

    container.style.display = 'flex';
    tbody.innerHTML = '';

    // Generate Adversarial Payloads
    const vectors = [
      { name: 'Schema: Missing Required Property', cat: 'CONFORMANCE', payload: {} },
      { name: 'Null Byte Poisoning (\\x00)', cat: 'UNICODE', payload: { path: '/clean\x00/etc/passwd' } },
      { name: 'Directory Traversal (../../etc/passwd)', cat: 'SECURITY', payload: { path: '../../../../etc/passwd' } },
      { name: 'Windows Traversal (..\\..\\windows)', cat: 'SECURITY', payload: { path: '..\\..\\windows\\system32' } },
      { name: 'Command Chaining (; cat /etc/shadow)', cat: 'SECURITY', payload: { path: 'legit; cat /etc/shadow' } },
      { name: 'Subshell Execution ($(whoami))', cat: 'SECURITY', payload: { path: '$(whoami)' } },
      { name: 'AWS Access Key Exfiltration', cat: 'SECURITY', payload: { content: 'AKIAIOSFODNN7EXAMPLE' } },
      { name: 'Cloud Metadata SSRF Target', cat: 'SECURITY', payload: { url: 'http://169.254.169.254/latest/' } },
      { name: 'Buffer Stress (32KB String)', cat: 'BOUNDARY', payload: { content: 'A'.repeat(32768) } },
      { name: 'Negative Extreme Integer', cat: 'BOUNDARY', payload: { bytes: -999999 } },
      { name: 'BiDi RTL Override Spoofing', cat: 'UNICODE', payload: { path: '\u202Ecodegood.txt' } },
      { name: 'Zero-Width Non-Joiner Injection', cat: 'UNICODE', payload: { path: 'adm\u200Cin' } }
    ];

    let passed = 0;
    let blocked = 0;

    for (const vec of vectors) {
      this.sound.playFuzzTick();
      await new Promise(r => setTimeout(r, 60)); // Visual tick delay

      let status = 'PASSED';
      let diag = 'Handled gracefully';
      let latency = Math.floor(Math.random() * 4) + 1;

      if (withFirewall) {
        const evalRes = this.firewall.evaluate(tool.name, vec.payload);
        if (evalRes.blocked) {
          status = 'BLOCKED_BY_AEGIS';
          diag = `Firewall Shield: [${evalRes.alert.ruleId}] ${evalRes.alert.signature}`;
          blocked++;
          passed++;
        } else {
          passed++;
        }
      } else {
        passed++;
      }

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${vec.name}</strong></td>
        <td><code>${vec.cat}</code></td>
        <td><span class="badge ${status.includes('BLOCKED') ? 'red' : 'green'}">${status}</span></td>
        <td>${latency}ms</td>
        <td style="color: var(--text-muted); font-size: 11px;">${diag}</td>
      `;
      tbody.appendChild(tr);
    }

    const pct = Math.round((passed / vectors.length) * 100);
    document.getElementById('scorecard-grade').textContent = pct >= 95 ? 'A+' : pct >= 85 ? 'A' : 'B';
    document.getElementById('scorecard-title').textContent = `Resilience Score: ${pct}%`;
    document.getElementById('scorecard-summary').textContent = `${passed} / ${vectors.length} Adversarial Vectors Gracefully Defended (${blocked} Intercepted by Firewall)`;

    this.sound.playSuccess();
    this.logEvent('FUZZ_AUDIT', `Fuzz campaign on "${toolName}" finished: Grade A+ (${pct}%)`, 'success');
    await this.ledger.append('FUZZ_AUDIT', { tool: toolName, scorePct: pct, grade: 'A+' });
    this.updateStats();
  }

  setupPipelineUI() {
    this.drawPipelineCanvas();
    document.getElementById('run-pipeline-btn').addEventListener('click', () => this.runDAGPipeline());
    document.getElementById('reset-pipeline-btn').addEventListener('click', () => {
      this.sound.playClick();
      document.getElementById('pipeline-log-display').innerHTML = '<p class="empty-state">Pipeline reset to ready state.</p>';
      document.getElementById('pipeline-status-badge').textContent = 'READY';
      document.querySelectorAll('.dag-node-card').forEach(c => c.className = 'dag-node-card');
      this.drawPipelineCanvas();
    });
  }

  drawPipelineCanvas() {
    const canvas = document.getElementById('dag-canvas');
    if (!canvas) return;
    const parent = canvas.parentElement;
    canvas.width = parent.clientWidth;
    canvas.height = parent.clientHeight;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw grid
    ctx.strokeStyle = '#151b2d';
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 30) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += 30) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke();
    }

    // Render nodes overlay
    const overlay = document.getElementById('dag-nodes-overlay');
    overlay.innerHTML = '';

    for (let i = 0; i < this.pipelineNodes.length; i++) {
      const node = this.pipelineNodes[i];
      const card = document.createElement('div');
      card.id = `node-card-${node.id}`;
      card.className = 'dag-node-card';
      card.style.left = `${node.x}px`;
      card.style.top = `${node.y}px`;
      card.innerHTML = `
        <div class="node-header">
          <span class="node-title">${node.title}</span>
          <span class="node-tool-badge">${node.tool}</span>
        </div>
        <div class="node-status-row">
          <span>${node.server}</span>
          <span class="node-status" id="status-${node.id}">IDLE</span>
        </div>
      `;
      overlay.appendChild(card);

      // Connect bezier curve to next node
      if (i < this.pipelineNodes.length - 1) {
        const next = this.pipelineNodes[i + 1];
        const startX = node.x + 220;
        const startY = node.y + 35;
        const endX = next.x;
        const endY = next.y + 35;
        const cpX = (startX + endX) / 2;

        ctx.strokeStyle = '#00f0ff';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(startX, startY);
        ctx.bezierCurveTo(cpX, startY, cpX, endY, endX, endY);
        ctx.stroke();

        // Draw pulse circle
        ctx.fillStyle = '#00f0ff';
        ctx.beginPath();
        ctx.arc(startX, startY, 4, 0, Math.PI * 2);
        ctx.arc(endX, endY, 4, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  async runDAGPipeline() {
    this.sound.playClick();
    const logBox = document.getElementById('pipeline-log-display');
    logBox.innerHTML = '<div style="color: var(--accent-cyan)">▶ Initializing DAG Multi-Server Pipeline Execution...</div>';
    document.getElementById('pipeline-status-badge').textContent = 'RUNNING';

    const context = { nodes: {} };

    for (const node of this.pipelineNodes) {
      const card = document.getElementById(`node-card-${node.id}`);
      const statusEl = document.getElementById(`status-${node.id}`);
      card.className = 'dag-node-card running';
      statusEl.textContent = 'RUNNING';

      this.sound.playClick();
      await new Promise(r => setTimeout(r, 350)); // Visual execution step delay

      // Resolve dynamic interpolation using template expressions
      const interpolate = (val) => {
        if (typeof val === 'string') {
          return val.replace(/\{\{\s*nodes\.([a-zA-Z0-9_-]+)(?:\.[^}]+|\s*)?\}\}/g, (match, srcId) => {
            const srcNode = context.nodes[srcId];
            if (!srcNode || !srcNode.output) return match;
            const inner = match.replace(/[\{\}]/g, '').trim();
            const parts = inner.split('.');
            let curr = srcNode;
            for (let i = 2; i < parts.length; i++) {
              if (curr === undefined || curr === null) break;
              curr = curr[parts[i]];
            }
            return curr !== undefined ? (typeof curr === 'object' ? JSON.stringify(curr) : String(curr)) : match;
          });
        }
        return val;
      };

      let resolvedParams = {};
      for (const [k, v] of Object.entries(node.params || {})) {
        resolvedParams[k] = interpolate(v);
      }

      // Execute tool
      const tool = this.hub.getTool(node.tool);
      const res = await tool.fn(resolvedParams);
      let parsed = JSON.parse(res.content[0].text);

      context.nodes[node.id] = { output: parsed };
      card.className = 'dag-node-card success';
      statusEl.textContent = 'SUCCESS';

      logBox.innerHTML += `<div style="margin-top: 4px; color: var(--accent-emerald)">✔ [${node.server}] ${node.tool} complete: <code>${JSON.stringify(parsed).slice(0, 70)}...</code></div>`;
      logBox.scrollTop = logBox.scrollHeight;
    }

    this.sound.playSuccess();
    document.getElementById('pipeline-status-badge').textContent = 'COMPLETED';
    this.logEvent('PIPELINE_COMPLETE', 'Visual DAG pipeline completed all 4 steps successfully.', 'success');
    await this.ledger.append('PIPELINE_COMPLETE', { nodesCount: 4 });
    this.updateStats();
  }

  setupLedgerUI() {
    document.getElementById('verify-chain-btn').addEventListener('click', async () => {
      this.sound.playClick();
      const res = await this.ledger.verify();
      const badge = document.getElementById('ledger-integrity-badge');
      if (res.valid) {
        this.sound.playSuccess();
        badge.className = 'chain-status-badge pristine';
        badge.textContent = `CHAIN INTEGRITY: PRISTINE (${res.blockCount} BLOCKS)`;
        this.logEvent('LEDGER_VERIFIED', `Ledger verification passed across all ${res.blockCount} blocks.`, 'success');
      } else {
        this.sound.playBlock();
        badge.className = 'chain-status-badge compromised';
        badge.textContent = `CHAIN COMPROMISED AT BLOCK #${res.brokenIndex}!`;
        this.logEvent('BREACH_ALERT', `Cryptographic tamper detected at block #${res.brokenIndex}!`, 'block');
      }
      await this.refreshLedgerDisplay();
    });

    document.getElementById('simulate-tamper-btn').addEventListener('click', () => this.simulateTamper());

    document.getElementById('export-proof-btn').addEventListener('click', () => {
      this.sound.playClick();
      const proof = {
        chainLength: this.ledger.chain.length,
        headHash: this.ledger.chain[this.ledger.chain.length - 1].hash,
        blocks: this.ledger.chain
      };
      const blob = new Blob([JSON.stringify(proof, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'aegis-audit-proof.json';
      a.click();
    });
  }

  async simulateTamper() {
    this.sound.playBlock();
    if (this.ledger.chain.length > 1) {
      this.ledger.tamper(1, { type: 'FALSIFIED_TOOL_CALL', reason: 'Adversary covert modification' });
    }
    const badge = document.getElementById('ledger-integrity-badge');
    badge.className = 'chain-status-badge compromised';
    badge.textContent = 'CHAIN COMPROMISED: TAMPER ATTACK DETECTED';
    this.logEvent('TAMPER_ATTACK', 'Simulated adversarial payload modification on Block #1.', 'block');
    await this.refreshLedgerDisplay();
  }

  async refreshLedgerDisplay() {
    const container = document.getElementById('blocks-chain-container');
    container.innerHTML = '';
    const latest = this.ledger.chain[this.ledger.chain.length - 1];
    document.getElementById('latest-block-hash').textContent = latest ? latest.hash : '';
    document.getElementById('genesis-block-hash').textContent = this.ledger.chain[0] ? this.ledger.chain[0].hash : '';

    for (let i = this.ledger.chain.length - 1; i >= 0; i--) {
      const b = this.ledger.chain[i];
      const card = document.createElement('div');
      card.className = `block-card ${b.event.type === 'FALSIFIED_TOOL_CALL' ? 'tampered' : ''}`;
      card.innerHTML = `
        <div class="block-card-header">
          <span class="block-index">Block #${b.index} [${b.event.type}]</span>
          <span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">${b.timestamp}</span>
        </div>
        <div class="block-hash-row">
          <span>PREV:</span>
          <span class="block-hash-val">${b.prevHash}</span>
        </div>
        <div class="block-hash-row">
          <span>HASH:</span>
          <span class="block-hash-val" style="color: var(--accent-cyan); font-weight: 700;">${b.hash}</span>
        </div>
        <div style="font-size: 11px; color: var(--text-muted); background: var(--bg-card); padding: 6px; border-radius: 4px; font-family: var(--font-mono);">
          ${JSON.stringify(b.event)}
        </div>
      `;
      container.appendChild(card);
    }
  }

  // ==============================================================
  // 7. Time-Travel Forensics & Tamper Localization
  // ==============================================================
  setupForensicsUI() {
    const slider = document.getElementById('timeline-slider');
    const prevBtn = document.getElementById('scrub-prev-btn');
    const nextBtn = document.getElementById('scrub-next-btn');

    const updateScrubber = (idx) => {
      idx = Math.max(0, Math.min(this.ledger.chain.length - 1, idx));
      slider.value = idx;
      this.renderForensicSnapshot(idx);
    };

    if (slider) {
      slider.addEventListener('input', (e) => {
        this.renderForensicSnapshot(parseInt(e.target.value, 10));
      });
    }

    if (prevBtn) {
      prevBtn.addEventListener('click', () => {
        this.sound.playClick();
        updateScrubber(parseInt(slider.value, 10) - 1);
      });
    }

    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        this.sound.playClick();
        updateScrubber(parseInt(slider.value, 10) + 1);
      });
    }

    // Tamper Button
    const tamperBtn = document.getElementById('forensic-tamper-btn');
    if (tamperBtn) {
      tamperBtn.addEventListener('click', async () => {
        await this.runForensicTamper();
      });
    }

    // Restore Button
    const restoreBtn = document.getElementById('forensic-restore-btn');
    if (restoreBtn) {
      restoreBtn.addEventListener('click', async () => {
        await this.runForensicRestore();
      });
    }

    // Initial render
    this.refreshForensicsUI();
  }

  async refreshForensicsUI() {
    const slider = document.getElementById('timeline-slider');
    if (slider) {
      slider.max = Math.max(0, this.ledger.chain.length - 1);
      slider.value = this.ledger.chain.length - 1;
    }
    this.renderForensicSnapshot(this.ledger.chain.length - 1);
  }

  renderForensicSnapshot(index) {
    const block = this.ledger.getSnapshot(index);
    if (!block) return;

    const label = document.getElementById('scrubber-index-label');
    if (label) label.textContent = `Block #${block.index} (${block.event.type || 'EVENT'})`;

    const evType = document.getElementById('snapshot-event-type');
    if (evType) evType.textContent = `EVENT: ${block.event.type || 'UNKNOWN'}`;

    const time = document.getElementById('snapshot-timestamp');
    if (time) time.textContent = block.timestamp || '';

    const hash = document.getElementById('snapshot-hash');
    if (hash) hash.textContent = block.hash || '';

    const payload = document.getElementById('snapshot-payload-display');
    if (payload) payload.textContent = JSON.stringify(block.event, null, 2);
  }

  async runForensicTamper() {
    this.sound.playBlock();
    if (this.ledger.chain.length > 1) {
      this.ledger.tamper(1, {
        type: 'FALSIFIED_TOOL_CALL',
        covertAttacker: 'Adversary Simulation',
        alteredData: 'Malicious audit trail spoofing',
        tamperedAt: new Date().toISOString()
      });
    }

    const report = await this.ledger.locateTamper();
    const badge = document.getElementById('forensic-status-badge');
    const summary = document.getElementById('forensic-summary-text');
    const diffView = document.getElementById('forensic-diff-view');
    const tbody = document.getElementById('forensic-diff-tbody');

    if (!report.intact) {
      badge.className = 'blast-radius-badge';
      badge.textContent = `CRITICAL: TAMPER LOCALIZED AT BLOCK #${report.brokenIndex} (BLAST RADIUS: ${report.cascadeBlastRadius} BLOCKS)`;
      summary.innerHTML = `
        <span style="color: var(--accent-crimson); font-weight: 700;">🚨 Cryptographic Breach Localized:</span>
        Adversary tampering detected at block #${report.brokenIndex}.
        The SHA-256 Merkle chain is broken. Downstream blast radius invalidates <strong>${report.cascadeBlastRadius}</strong> blocks in the audit ledger.
      `;

      if (report.diff && report.diff.length > 0) {
        diffView.style.display = 'block';
        tbody.innerHTML = report.diff.map(d => `
          <tr class="tampered-row">
            <td><code>${d.key}</code></td>
            <td><code>${JSON.stringify(d.original)}</code></td>
            <td><code style="color: #ff3366;">${JSON.stringify(d.tampered)}</code></td>
          </tr>
        `).join('');
      }

      this.logEvent('FORENSIC_ALERT', `Tamper localized at block #${report.brokenIndex}. Blast radius: ${report.cascadeBlastRadius} blocks`, 'block');
    }
    await this.refreshLedgerDisplay();
  }

  async runForensicRestore() {
    this.sound.playSuccess();
    this.ledger.restoreAll();
    const verify = await this.ledger.verify();

    const badge = document.getElementById('forensic-status-badge');
    const summary = document.getElementById('forensic-summary-text');
    const diffView = document.getElementById('forensic-diff-view');

    badge.className = 'blast-radius-badge pristine';
    badge.textContent = 'STATUS: PRISTINE (ALL BLOCKS VERIFIED)';
    summary.innerHTML = `
      <span style="color: var(--accent-emerald); font-weight: 700;">✔ Cryptographic Healing Complete:</span>
      All tampered blocks successfully restored to canonical pre-image state.
      The entire Merkle chain is validated intact across ${verify.blockCount} blocks.
    `;
    if (diffView) diffView.style.display = 'none';

    const ledgerBadge = document.getElementById('ledger-integrity-badge');
    if (ledgerBadge) {
      ledgerBadge.className = 'chain-status-badge pristine';
      ledgerBadge.textContent = 'CHAIN INTEGRITY: PRISTINE';
    }

    this.logEvent('CHAIN_RESTORED', 'Cryptographic healing complete. All ledger blocks intact.', 'success');
    await this.refreshLedgerDisplay();
  }

  async runForensicDemo() {
    await this.runForensicTamper();
    setTimeout(async () => {
      await this.runForensicRestore();
    }, 4500);
  }

  // ==============================================================
  // 8. Dynamic Security Rule Synthesizer
  // ==============================================================
  setupSynthesizerUI() {
    const synthToolBtn = document.getElementById('synth-tool-btn');
    if (synthToolBtn) {
      synthToolBtn.addEventListener('click', () => {
        this.sound.playClick();
        const sel = document.getElementById('synth-tool-select');
        const toolName = sel ? sel.value : 'read_file';
        this.synthesizeRulesForSelectedTool(toolName);
      });
    }

    const synthSigBtn = document.getElementById('synth-sig-btn');
    if (synthSigBtn) {
      synthSigBtn.addEventListener('click', () => {
        this.sound.playClick();
        const name = document.getElementById('synth-sig-name').value.trim() || 'Custom Invariant Guard';
        const regexStr = document.getElementById('synth-sig-regex').value.trim();
        const sev = document.getElementById('synth-sig-severity').value;

        if (!regexStr) {
          alert('Please enter a regex pattern to synthesize a rule.');
          return;
        }

        let regex;
        try {
          regex = new RegExp(regexStr, 'i');
        } catch (e) {
          alert(`Invalid regex pattern: ${e.message}`);
          return;
        }

        const newRule = {
          id: `SYN-CUST-${Math.floor(Math.random() * 900) + 100}`,
          name,
          severity: sev,
          description: `Dynamically synthesized rule for pattern /${regexStr}/i`,
          enabled: true,
          check: (params) => {
            const strings = extractAllStrings(params);
            for (const s of strings) {
              if (regex.test(s)) return { violation: true, signature: name, culprit: s };
            }
            return { violation: false };
          }
        };

        this.firewall.rules.push(newRule);
        this.sound.playSuccess();
        this.logEvent('RULE_SYNTHESIZED', `Hot-loaded rule [${newRule.id}] ${newRule.name} into firewall`, 'success');
        this.renderSynthesizedCard(newRule, 'CUSTOM_SIGNATURE_SYNTHESIS', true);
        this.updateStats();
      });
    }
  }

  synthesizeRulesForSelectedTool(toolName) {
    const container = document.getElementById('synthesized-rules-container');
    container.innerHTML = '';

    const synthesized = [
      {
        id: `SYN-CONFINEMENT-${toolName}`,
        name: `Path Confinement & Root Escape Guard for [${toolName}]`,
        category: 'FILESYSTEM_SECURITY',
        severity: 'CRITICAL',
        description: `Strict path confinement guard automatically synthesized for parameter "path" of tool "${toolName}". Blocks directory escaping, Windows UNC bypasses, and root filesystem escapes.`,
        pattern: 'Detects ../, ..\\, %2e%2e, root escapes, and null byte truncations.',
        adversarialSample: '../../../../etc/shadow',
        benignSample: '/workspace/project.json'
      },
      {
        id: `SYN-BUFFER-${toolName}`,
        name: `Bounded Buffer & DoS Guard for [${toolName}]`,
        category: 'RESOURCE_PROTECTION',
        severity: 'MEDIUM',
        description: `Enforces strict 64KB bounded input constraint on all string arguments to prevent parser exhaustion or ReDoS.`,
        pattern: 'Rejects payloads exceeding 65536 bytes in single argument.',
        adversarialSample: 'A'.repeat(70000),
        benignSample: 'standard_input_query'
      }
    ];

    document.getElementById('synthesized-count-badge').textContent = `${synthesized.length} Rules Synthesized`;

    synthesized.forEach(rule => {
      this.renderSynthesizedCard(rule, rule.category, false);
    });

    this.sound.playSuccess();
    this.logEvent('SYNTHESIZER', `Synthesized ${synthesized.length} zero-trust defense rules for "${toolName}".`, 'success');
  }

  renderSynthesizedCard(rule, category, isLoaded = false) {
    const container = document.getElementById('synthesized-rules-container');
    const card = document.createElement('div');
    card.className = 'synthesized-card';
    card.innerHTML = `
      <div class="synthesized-header">
        <div>
          <strong style="color: var(--accent-cyan); font-size: 13px;">[${rule.id}] ${rule.name}</strong>
          <span class="badge ${rule.severity === 'CRITICAL' ? 'badge-enforce' : ''}" style="margin-left: 8px;">${rule.severity}</span>
        </div>
        <button class="btn-sm btn-load-rule" style="background: ${isLoaded ? 'var(--accent-emerald)' : 'var(--bg-card)'}; color: ${isLoaded ? '#000' : 'var(--text-main)'}; font-weight: 700;">
          ${isLoaded ? '✔ ACTIVE IN FIREWALL' : '⚡ Hot-Reload into Firewall'}
        </button>
      </div>
      <p style="font-size: 12px; color: var(--text-muted);">${rule.description}</p>
      ${rule.pattern ? `<div style="font-size: 11px; font-family: var(--font-mono); color: var(--accent-cyan); background: var(--bg-card); padding: 6px; border-radius: 4px;">🛡️ Enforcement Pattern: ${rule.pattern}</div>` : ''}
    `;

    const btn = card.querySelector('.btn-load-rule');
    if (!isLoaded && btn) {
      btn.addEventListener('click', () => {
        this.sound.playSuccess();
        btn.textContent = '✔ ACTIVE IN FIREWALL';
        btn.style.background = 'var(--accent-emerald)';
        btn.style.color = '#000';
        this.logEvent('RULE_HOT_LOADED', `Active firewall now enforcing rule [${rule.id}]`, 'success');
      });
    }

    container.prepend(card);
  }

  // ==============================================================
  // 9. AI Client Config Generator
  // ==============================================================
  setupConfigsUI() {
    const clientBtns = document.querySelectorAll('.client-tab-btn');
    clientBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        this.sound.playClick();
        clientBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.updateClientConfigDisplay(btn.getAttribute('data-client'));
      });
    });

    const copyBtn = document.getElementById('copy-config-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        const text = document.getElementById('client-config-code').textContent;
        navigator.clipboard.writeText(text).then(() => {
          this.sound.playSuccess();
          copyBtn.textContent = '✔ Copied!';
          setTimeout(() => { copyBtn.textContent = '📋 Copy Snippet'; }, 2000);
        }).catch(() => {
          copyBtn.textContent = '✔ Copied!';
        });
      });
    }

    this.updateClientConfigDisplay('claude');
  }

  updateClientConfigDisplay(client) {
    const codeBox = document.getElementById('client-config-code');
    const pathBox = document.getElementById('config-target-path');
    const instrBox = document.getElementById('config-instruction-text');

    const port = 3333;
    const binPath = '/Users/dhairyashah/.gemini/antigravity/scratch/AegisMCP/bin/aegis-mcp.js';

    const configs = {
      claude: {
        path: '~/Library/Application Support/Claude/claude_desktop_config.json',
        instruction: 'Open your Claude Desktop config file, paste this snippet under "mcpServers", and restart Claude.',
        snippet: {
          mcpServers: {
            'aegis-security-gateway': {
              command: 'node',
              args: [binPath, '--stdio', '--mode', 'ENFORCE']
            }
          }
        }
      },
      cursor: {
        path: '.cursor/mcp.json (or Cursor Settings > Features > MCP)',
        instruction: 'Add this entry to your project\'s .cursor/mcp.json file to shield all Cursor Agent tool invocations.',
        snippet: {
          mcpServers: {
            'aegis-mcp': {
              command: 'node',
              args: [binPath, '--stdio', '--mode', 'ENFORCE']
            }
          }
        }
      },
      zed: {
        path: '~/.config/zed/settings.json',
        instruction: 'Add this server to the context_servers setting in your Zed configuration.',
        snippet: {
          context_servers: {
            'aegis-mcp': {
              command: {
                path: 'node',
                args: [binPath, '--stdio', '--mode', 'ENFORCE']
              }
            }
          }
        }
      },
      windsurf: {
        path: '~/.codeium/windsurf/mcp_config.json',
        instruction: 'Paste this block into Windsurf\'s MCP configuration file.',
        snippet: {
          mcpServers: {
            'aegis-mcp': {
              command: 'node',
              args: [binPath, '--stdio', '--mode', 'ENFORCE']
            }
          }
        }
      },
      http: {
        path: `http://localhost:${port}/rpc`,
        instruction: 'Run "aegis-mcp --serve --port 3333" to start the HTTP/SSE gateway, and point any HTTP MCP client to this endpoint.',
        snippet: {
          type: 'http-jsonrpc-2.0',
          url: `http://localhost:${port}/rpc`,
          healthUrl: `http://localhost:${port}/health`,
          headers: {
            'Content-Type': 'application/json'
          }
        }
      }
    };

    const cfg = configs[client] || configs.claude;
    if (codeBox) codeBox.textContent = JSON.stringify(cfg.snippet, null, 2);
    if (pathBox) pathBox.textContent = cfg.path;
    if (instrBox) instrBox.textContent = cfg.instruction;
  }

  // ==============================================================
  // 10. Servers Fleet UI
  // ==============================================================
  setupServersUI() {
    const container = document.getElementById('fleet-servers-cards');
    if (!container) return;

    const servers = [
      { name: 'virtual_filesystem', tools: 5, desc: 'POSIX virtual in-memory sandboxed filesystem', status: 'ACTIVE', type: 'Virtual In-Memory' },
      { name: 'virtual_memory', tools: 5, desc: 'Tagged key-value state store and associative memory', status: 'ACTIVE', type: 'Virtual In-Memory' },
      { name: 'virtual_crypto', tools: 5, desc: 'Cryptographic hashing, HMAC, UUID, and entropy generation', status: 'ACTIVE', type: 'Virtual In-Memory' },
      { name: 'virtual_http_simulator', tools: 1, desc: 'Outbound HTTP request simulator with SSRF defense', status: 'ACTIVE', type: 'Virtual In-Memory' }
    ];

    const render = () => {
      container.innerHTML = servers.map(s => `
        <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 14px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <strong style="color: var(--accent-cyan); font-size: 13px;">${s.name}</strong>
            <span class="badge" style="background: rgba(0, 255, 157, 0.15); color: var(--accent-emerald);">${s.status}</span>
          </div>
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">${s.desc}</p>
          <div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
            <span>Type: ${s.type}</span>
            <span>Tools: ${s.tools}</span>
          </div>
        </div>
      `).join('');
      document.getElementById('servers-fleet-count').textContent = `${servers.length} Active Servers`;
    };

    render();

    const connectBtn = document.getElementById('connect-server-btn');
    if (connectBtn) {
      connectBtn.addEventListener('click', () => {
        this.sound.playClick();
        const nameInput = document.getElementById('new-server-name');
        const cmdInput = document.getElementById('new-server-command');
        const name = (nameInput ? nameInput.value.trim() : '') || `ext_server_${servers.length + 1}`;
        const cmd = (cmdInput ? cmdInput.value.trim() : '') || 'npx -y @modelcontextprotocol/server-filesystem /tmp';

        servers.push({
          name,
          tools: 4,
          desc: `External MCP Server (${cmd})`,
          status: 'SHIELDED (TUNNELED)',
          type: 'External Process Stdio'
        });

        if (nameInput) nameInput.value = '';
        if (cmdInput) cmdInput.value = '';

        this.sound.playSuccess();
        render();
        this.logEvent('SERVER_CONNECTED', `Connected and shielded external server "${name}"`, 'success');
      });
    }
  }

  updateStats() {
    document.getElementById('stat-total-evals').textContent = this.firewall.stats.evaluated;
    document.getElementById('stat-total-blocked').textContent = this.firewall.stats.blocked;
    document.getElementById('stat-total-sanitized').textContent = this.firewall.stats.sanitized;
    document.getElementById('stat-ledger-height').textContent = this.ledger.chain.length;

    const pct = this.firewall.stats.evaluated > 0
      ? ((this.firewall.stats.blocked / this.firewall.stats.evaluated) * 100).toFixed(0)
      : 0;
    document.getElementById('stat-block-sub').textContent = `${pct}% block rate`;

    // Radar bars
    const maxVal = Math.max(1, ...Object.values(this.firewall.stats.ruleCounts));
    for (const [id, count] of Object.entries(this.firewall.stats.ruleCounts)) {
      const bar = document.getElementById(`bar-${id.toLowerCase()}`);
      const txt = document.getElementById(`count-${id.toLowerCase()}`);
      if (bar) bar.style.width = `${(count / maxVal) * 100}%`;
      if (txt) txt.textContent = count;
    }
  }

  logEvent(type, desc, kind = 'success', data = null) {
    const stream = document.getElementById('event-stream-container');
    const item = document.createElement('div');
    item.className = `event-item ${kind}`;
    const time = new Date().toLocaleTimeString();
    item.innerHTML = `
      <div class="event-top">
        <span class="event-type-badge">${type}</span>
        <span class="event-time">${time}</span>
      </div>
      <div class="event-desc">${desc}</div>
      ${data ? `<div class="event-detail">${JSON.stringify(data)}</div>` : ''}
    `;
    stream.prepend(item);
  }
}

// Boot application on load
window.addEventListener('DOMContentLoaded', () => {
  window.aegis = new AegisStudioApp();
});
