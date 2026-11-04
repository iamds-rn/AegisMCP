/**
 * AegisMCP - Virtual In-Memory MCP Server Hub
 * Standalone, zero-install virtual MCP servers conforming to MCP 2024-11-05 spec.
 */

'use strict';

const crypto = require('node:crypto');
const { calculateShannonEntropy } = require('../firewall/rules');

// -------------------------------------------------------------
// 1. In-Memory Virtual FileSystem Server
// -------------------------------------------------------------
class VirtualFilesystemServer {
  constructor() {
    this.name = 'virtual_filesystem';
    this.version = '1.0.0';
    this.description = 'In-memory sandboxed POSIX-style filesystem';
    this.files = new Map([
      ['/workspace/project.json', JSON.stringify({ name: 'AlphaPilot', version: '2.4.0', status: 'active' }, null, 2)],
      ['/workspace/src/index.js', 'console.log("System initialized");\nmodule.exports = { ready: true };'],
      ['/workspace/notes.txt', 'Review security credentials and rotation policy before deployment.']
    ]);
  }

  getTools() {
    return [
      {
        name: 'read_file',
        description: 'Read textual content of a file at the specified virtual path.',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Absolute or relative file path (e.g. /workspace/notes.txt)' }
          },
          required: ['path']
        }
      },
      {
        name: 'write_file',
        description: 'Write or overwrite content of a file at the specified virtual path.',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Target file path' },
            content: { type: 'string', description: 'Text content to write' }
          },
          required: ['path', 'content']
        }
      },
      {
        name: 'list_files',
        description: 'List all files present in a given virtual directory path.',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Directory path (e.g. /workspace)' }
          },
          required: ['path']
        }
      },
      {
        name: 'delete_file',
        description: 'Delete a file at the specified virtual path.',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'File path to delete' }
          },
          required: ['path']
        }
      },
      {
        name: 'file_stat',
        description: 'Retrieve metadata and size for a file.',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'File path' }
          },
          required: ['path']
        }
      }
    ];
  }

  async callTool(name, args = {}) {
    const normalizePath = (p) => (p && typeof p === 'string' ? (p.startsWith('/') ? p : '/' + p) : '/');

    switch (name) {
      case 'read_file': {
        const p = normalizePath(args.path);
        if (!this.files.has(p)) {
          throw new Error(`File not found: ${p}`);
        }
        return { content: [{ type: 'text', text: this.files.get(p) }] };
      }
      case 'write_file': {
        const p = normalizePath(args.path);
        const content = String(args.content !== undefined ? args.content : '');
        this.files.set(p, content);
        return { content: [{ type: 'text', text: `Successfully wrote ${content.length} bytes to ${p}` }] };
      }
      case 'list_files': {
        const dir = normalizePath(args.path);
        const matches = [];
        for (const key of this.files.keys()) {
          if (key.startsWith(dir)) {
            matches.push(key);
          }
        }
        return { content: [{ type: 'text', text: JSON.stringify({ directory: dir, files: matches }, null, 2) }] };
      }
      case 'delete_file': {
        const p = normalizePath(args.path);
        if (!this.files.has(p)) {
          throw new Error(`Cannot delete: file not found: ${p}`);
        }
        this.files.delete(p);
        return { content: [{ type: 'text', text: `Deleted file ${p}` }] };
      }
      case 'file_stat': {
        const p = normalizePath(args.path);
        if (!this.files.has(p)) {
          throw new Error(`File not found: ${p}`);
        }
        const text = this.files.get(p);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  path: p,
                  sizeBytes: Buffer.byteLength(text, 'utf8'),
                  lines: text.split('\n').length,
                  exists: true
                },
                null,
                2
              )
            }
          ]
        };
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
}

// -------------------------------------------------------------
// 2. In-Memory Virtual Memory & KV Server
// -------------------------------------------------------------
class VirtualMemoryServer {
  constructor() {
    this.name = 'virtual_memory';
    this.version = '1.0.0';
    this.description = 'Key-value state store and tagged associative memory';
    this.store = new Map([
      ['system:status', { value: 'operational', tags: ['system', 'health'], updatedAt: new Date().toISOString() }],
      ['config:tier', { value: 'enterprise', tags: ['config', 'billing'], updatedAt: new Date().toISOString() }]
    ]);
  }

  getTools() {
    return [
      {
        name: 'set_key',
        description: 'Store a key-value pair with optional classification tags.',
        inputSchema: {
          type: 'object',
          properties: {
            key: { type: 'string', description: 'Identifier key' },
            value: { type: 'string', description: 'Value payload' },
            tags: { type: 'array', items: { type: 'string' }, description: 'Optional tags' }
          },
          required: ['key', 'value']
        }
      },
      {
        name: 'get_key',
        description: 'Retrieve the value and metadata of a stored key.',
        inputSchema: {
          type: 'object',
          properties: {
            key: { type: 'string', description: 'Identifier key' }
          },
          required: ['key']
        }
      },
      {
        name: 'search_keys',
        description: 'Search across keys, values, and tags.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search term or keyword' }
          },
          required: ['query']
        }
      },
      {
        name: 'delete_key',
        description: 'Delete a key from memory store.',
        inputSchema: {
          type: 'object',
          properties: {
            key: { type: 'string', description: 'Key to delete' }
          },
          required: ['key']
        }
      },
      {
        name: 'list_keys',
        description: 'List all existing memory keys with their tags.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }
    ];
  }

  async callTool(name, args = {}) {
    switch (name) {
      case 'set_key': {
        const { key, value, tags = [] } = args;
        if (!key) throw new Error('Parameter "key" is required');
        this.store.set(String(key), {
          value,
          tags: Array.isArray(tags) ? tags : [String(tags)],
          updatedAt: new Date().toISOString()
        });
        return { content: [{ type: 'text', text: `Key "${key}" successfully saved.` }] };
      }
      case 'get_key': {
        const key = String(args.key || '');
        if (!this.store.has(key)) {
          throw new Error(`Key not found: ${key}`);
        }
        return { content: [{ type: 'text', text: JSON.stringify(this.store.get(key), null, 2) }] };
      }
      case 'search_keys': {
        const query = String(args.query || '').toLowerCase();
        const results = [];
        for (const [k, v] of this.store.entries()) {
          const valStr = JSON.stringify(v.value).toLowerCase();
          const tagMatch = v.tags.some(t => t.toLowerCase().includes(query));
          if (k.toLowerCase().includes(query) || valStr.includes(query) || tagMatch) {
            results.push({ key: k, entry: v });
          }
        }
        return { content: [{ type: 'text', text: JSON.stringify({ query, count: results.length, matches: results }, null, 2) }] };
      }
      case 'delete_key': {
        const key = String(args.key || '');
        if (!this.store.has(key)) {
          throw new Error(`Key not found: ${key}`);
        }
        this.store.delete(key);
        return { content: [{ type: 'text', text: `Key "${key}" deleted.` }] };
      }
      case 'list_keys': {
        const list = Array.from(this.store.entries()).map(([k, v]) => ({ key: k, tags: v.tags, updatedAt: v.updatedAt }));
        return { content: [{ type: 'text', text: JSON.stringify(list, null, 2) }] };
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
}

// -------------------------------------------------------------
// 3. In-Memory Virtual Crypto Vault Server
// -------------------------------------------------------------
class VirtualCryptoServer {
  constructor() {
    this.name = 'virtual_crypto';
    this.version = '1.0.0';
    this.description = 'Cryptographic hashing, HMAC signing, token generation, and entropy analysis';
  }

  getTools() {
    return [
      {
        name: 'hash_sha256',
        description: 'Calculate cryptographic SHA-256 digest of input text.',
        inputSchema: {
          type: 'object',
          properties: {
            text: { type: 'string', description: 'Plaintext input string' }
          },
          required: ['text']
        }
      },
      {
        name: 'hmac_sign',
        description: 'Generate HMAC-SHA256 signature for message using a secret key.',
        inputSchema: {
          type: 'object',
          properties: {
            secret: { type: 'string', description: 'Secret signing key' },
            message: { type: 'string', description: 'Message payload to sign' }
          },
          required: ['secret', 'message']
        }
      },
      {
        name: 'generate_token',
        description: 'Generate a cryptographically secure random token.',
        inputSchema: {
          type: 'object',
          properties: {
            bytes: { type: 'number', description: 'Number of random bytes (default: 32)' },
            format: { type: 'string', enum: ['hex', 'base64'], description: 'Encoding format' }
          }
        }
      },
      {
        name: 'eval_entropy',
        description: 'Calculate Shannon entropy (bits per character) of a string.',
        inputSchema: {
          type: 'object',
          properties: {
            text: { type: 'string', description: 'String to analyze' }
          },
          required: ['text']
        }
      }
    ];
  }

  async callTool(name, args = {}) {
    switch (name) {
      case 'hash_sha256': {
        const text = String(args.text !== undefined ? args.text : '');
        const hash = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
        return { content: [{ type: 'text', text: JSON.stringify({ algorithm: 'SHA-256', inputLength: text.length, hash }, null, 2) }] };
      }
      case 'hmac_sign': {
        const secret = String(args.secret || '');
        const message = String(args.message || '');
        const signature = crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');
        return { content: [{ type: 'text', text: JSON.stringify({ algorithm: 'HMAC-SHA256', signature }, null, 2) }] };
      }
      case 'generate_token': {
        const byteCount = Math.min(Math.max(parseInt(args.bytes, 10) || 32, 8), 128);
        const format = args.format === 'base64' ? 'base64' : 'hex';
        const token = crypto.randomBytes(byteCount).toString(format);
        const entropy = calculateShannonEntropy(token);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  token,
                  bytes: byteCount,
                  format,
                  shannonEntropy: Number(entropy.toFixed(3))
                },
                null,
                2
              )
            }
          ]
        };
      }
      case 'eval_entropy': {
        const text = String(args.text !== undefined ? args.text : '');
        const entropy = calculateShannonEntropy(text);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  length: text.length,
                  shannonEntropy: Number(entropy.toFixed(4)),
                  classification: entropy > 4.5 ? 'HIGH_ENTROPY (Likely Cryptographic Secret/Key)' : entropy > 3.0 ? 'MEDIUM_ENTROPY (Normal Text/Code)' : 'LOW_ENTROPY (Repetitive Data)'
                },
                null,
                2
              )
            }
          ]
        };
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
}

// -------------------------------------------------------------
// 4. In-Memory Virtual HTTP Simulator Server
// -------------------------------------------------------------
class VirtualHttpSimulatorServer {
  constructor() {
    this.name = 'virtual_http_simulator';
    this.version = '1.0.0';
    this.description = 'Simulated outbound network requester with mock APIs and SSRF guard target';
  }

  getTools() {
    return [
      {
        name: 'fetch_url',
        description: 'Simulate an outbound HTTP request to an external API endpoint.',
        inputSchema: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'Target destination URL' },
            method: { type: 'string', enum: ['GET', 'POST'], description: 'HTTP method' }
          },
          required: ['url']
        }
      }
    ];
  }

  async callTool(name, args = {}) {
    if (name === 'fetch_url') {
      const url = String(args.url || '');
      // Mock endpoints
      if (url.includes('api.github.com/status')) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ status: 'all systems operational', region: 'global', latencyMs: 14 }, null, 2)
            }
          ]
        };
      } else if (url.includes('weather.mock')) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ city: 'San Francisco', tempF: 62, condition: 'Partly Cloudy' }, null, 2)
            }
          ]
        };
      } else {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  url,
                  statusCode: 200,
                  simulated: true,
                  headers: { 'content-type': 'application/json' },
                  body: { message: 'Mock response from virtual endpoint', timestamp: new Date().toISOString() }
                },
                null,
                2
              )
            }
          ]
        };
      }
    }
    throw new Error(`Unknown tool: ${name}`);
  }
}

// -------------------------------------------------------------
// Hub Manager
// -------------------------------------------------------------
class VirtualHub {
  constructor() {
    this.servers = new Map();
    this.registerServer(new VirtualFilesystemServer());
    this.registerServer(new VirtualMemoryServer());
    this.registerServer(new VirtualCryptoServer());
    this.registerServer(new VirtualHttpSimulatorServer());
  }

  registerServer(server) {
    this.servers.set(server.name, server);
  }

  listServers() {
    return Array.from(this.servers.values()).map(s => ({
      name: s.name,
      version: s.version,
      description: s.description,
      toolCount: s.getTools().length
    }));
  }

  getServer(name) {
    return this.servers.get(name);
  }

  listAllTools() {
    const allTools = [];
    for (const [serverName, server] of this.servers.entries()) {
      for (const tool of server.getTools()) {
        allTools.push({
          ...tool,
          serverName
        });
      }
    }
    return allTools;
  }

  async executeTool(serverName, toolName, args = {}) {
    const server = this.servers.get(serverName);
    if (!server) {
      throw new Error(`Server not found: ${serverName}`);
    }
    return await server.callTool(toolName, args);
  }
}

module.exports = {
  VirtualHub,
  VirtualFilesystemServer,
  VirtualMemoryServer,
  VirtualCryptoServer,
  VirtualHttpSimulatorServer
};
