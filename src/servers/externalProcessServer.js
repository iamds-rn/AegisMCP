/**
 * AegisMCP - External MCP Server Proxy & Process Manager
 * Spawns and manages external MCP server processes over stdio (or connects over HTTP/SSE),
 * dynamically discovers tools, and proxies tool invocations through the zero-trust firewall.
 */

'use strict';

const { spawn } = require('node:child_process');
const readline = require('node:readline');
const http = require('node:http');
const https = require('node:https');
const { PROTOCOL_VERSION, createRequest, parseMessage } = require('../protocol/jsonrpc');

/**
 * Robust shell command tokenizer that preserves quoted arguments with whitespace.
 */
function tokenizeCommand(cmdStr) {
  if (!cmdStr || typeof cmdStr !== 'string') return [];
  const tokens = [];
  let current = '';
  let inDouble = false;
  let inSingle = false;
  let escaped = false;

  for (let i = 0; i < cmdStr.length; i++) {
    const ch = cmdStr[i];

    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }

    if (ch === '\\' && !inSingle) {
      escaped = true;
      continue;
    }

    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }

    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }

    if (/\s/.test(ch) && !inDouble && !inSingle) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

class ExternalProcessServer {
  /**
   * @param {object} options
   * @param {string} options.name - Unique identifier name for this server (e.g. 'ext_filesystem')
   * @param {string} [options.command] - Shell command or binary to spawn (e.g. 'npx -y @modelcontextprotocol/server-filesystem /tmp')
   * @param {Array<string>} [options.args] - Process arguments
   * @param {string} [options.url] - Optional HTTP/SSE URL if connecting via network
   * @param {object} [options.env] - Environment variables
   * @param {number} [options.timeoutMs] - Request timeout (default: 15000ms)
   */
  constructor(options = {}) {
    if (!options.name) throw new Error('ExternalProcessServer requires a unique "name"');
    this.name = options.name;
    this.command = options.command || null;
    this.args = options.args || [];
    this.url = options.url || null;
    this.env = options.env || {};
    this.timeoutMs = options.timeoutMs || 15000;
    this.version = '1.0.0';
    this.description = options.description || `External MCP Server (${this.command || this.url})`;

    this.process = null;
    this.rl = null;
    this.isReady = false;
    this.tools = [];
    this.pendingRequests = new Map();
    this.nextRequestId = 1000;
    this.status = 'DISCONNECTED';
  }

  /**
   * Starts the external server process and performs the initial MCP handshake.
   */
  async start() {
    if (this.url) {
      return await this._initNetworkServer();
    }

    if (!this.command) {
      throw new Error(`ExternalProcessServer "${this.name}" has no command or url configured.`);
    }

    return new Promise((resolve, reject) => {
      try {
        this.status = 'SPAWNING';
        // Handle command string with arguments if passed as single string
        let cmd = this.command;
        let cmdArgs = [...this.args];
        if (cmdArgs.length === 0 && cmd.includes(' ')) {
          const parts = tokenizeCommand(cmd);
          cmd = parts[0] || this.command;
          cmdArgs = parts.slice(1);
        }

        this.process = spawn(cmd, cmdArgs, {
          env: { ...process.env, ...this.env },
          stdio: ['pipe', 'pipe', 'pipe']
        });

        this.rl = readline.createInterface({
          input: this.process.stdout,
          terminal: false
        });

        this.rl.on('line', (line) => {
          this._handleStdioLine(line);
        });

        this.process.stderr.on('data', (data) => {
          // Keep track of stderr without crashing
          const str = data.toString().trim();
          if (str) {
            // Can be useful for debugging external server issues
          }
        });

        this.process.on('error', (err) => {
          this.status = 'ERROR';
          this._rejectAllPending(new Error(`External process error: ${err.message}`));
          reject(err);
        });

        this.process.on('exit', (code, signal) => {
          this.status = 'TERMINATED';
          this.isReady = false;
          this._rejectAllPending(new Error(`External process exited with code ${code} (${signal})`));
        });

        // Send MCP Protocol Handshake
        this._handshake()
          .then(() => {
            this.status = 'CONNECTED';
            this.isReady = true;
            resolve(this);
          })
          .catch(reject);
      } catch (err) {
        this.status = 'ERROR';
        reject(err);
      }
    });
  }

  _handleStdioLine(line) {
    const trimmed = line.trim();
    if (!trimmed) return;

    const parsed = parseMessage(trimmed);
    if (!parsed.ok) return;

    const msg = parsed.message;
    // Check if this is a response to a pending request
    if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined) && this.pendingRequests.has(msg.id)) {
      const { resolve, reject, timer } = this.pendingRequests.get(msg.id);
      clearTimeout(timer);
      this.pendingRequests.delete(msg.id);

      if (msg.error) {
        reject(new Error(msg.error.message || `JSON-RPC error ${msg.error.code}`));
      } else {
        resolve(msg.result);
      }
    }
  }

  _rejectAllPending(err) {
    for (const [, { reject, timer }] of this.pendingRequests.entries()) {
      clearTimeout(timer);
      reject(err);
    }
    this.pendingRequests.clear();
  }

  /**
   * Sends a JSON-RPC request to the child process stdio and waits for the response.
   */
  _sendRequest(method, params = {}) {
    return new Promise((resolve, reject) => {
      if (!this.process || this.status !== 'CONNECTED' && this.status !== 'SPAWNING') {
        return reject(new Error(`Server "${this.name}" is not connected (status: ${this.status})`));
      }

      const id = ++this.nextRequestId;
      const req = createRequest(method, params, id);

      const timer = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Request timeout (${this.timeoutMs}ms) for method "${method}"`));
        }
      }, this.timeoutMs);

      this.pendingRequests.set(id, { resolve, reject, timer });

      try {
        this.process.stdin.write(JSON.stringify(req) + '\n');
      } catch (err) {
        clearTimeout(timer);
        this.pendingRequests.delete(id);
        reject(err);
      }
    });
  }

  /**
   * MCP Protocol handshake: initialize -> notifications/initialized -> tools/list
   */
  async _handshake() {
    // 1. Initialize
    const initResult = await this._sendRequest('initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'AegisMCP-ProxyTunnel', version: '1.0.0' }
    });

    if (initResult && initResult.serverInfo) {
      this.description = `[${initResult.serverInfo.name} v${initResult.serverInfo.version || '1.0'}] Proxied via Aegis`;
    }

    // 2. Initialized notification (no response expected)
    try {
      this.process.stdin.write(JSON.stringify({
        jsonrpc: '2.0',
        method: 'notifications/initialized',
        params: {}
      }) + '\n');
    } catch {
      // Non-fatal if notification fails
    }

    // 3. Discover Tools
    await this.refreshTools();
  }

  async _initNetworkServer() {
    this.status = 'CONNECTED';
    this.isReady = true;
    await this.refreshTools();
    return this;
  }

  /**
   * Queries the external server's tools/list endpoint to discover all tools.
   */
  async refreshTools() {
    try {
      let result;
      if (this.url) {
        result = await this._sendHttpRequest('tools/list', {});
      } else {
        result = await this._sendRequest('tools/list', {});
      }

      if (result && Array.isArray(result.tools)) {
        this.tools = result.tools.map(t => ({
          name: t.name,
          description: t.description || `Tool provided by ${this.name}`,
          inputSchema: t.inputSchema || { type: 'object', properties: {} },
          serverName: this.name
        }));
      }
      return this.tools;
    } catch (err) {
      this.tools = [];
      throw err;
    }
  }

  _sendHttpRequest(method, params = {}) {
    return new Promise((resolve, reject) => {
      const u = new URL(this.url);
      const isHttps = u.protocol === 'https:';
      const lib = isHttps ? https : http;

      const payload = JSON.stringify(createRequest(method, params, ++this.nextRequestId));
      const req = lib.request(u, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: this.timeoutMs
      }, (res) => {
        res.on('error', reject);
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.error) {
              reject(new Error(parsed.error.message || 'JSON-RPC Error'));
            } else {
              resolve(parsed.result);
            }
          } catch (e) {
            reject(new Error(`Failed to parse response: ${e.message}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`HTTP request timeout after ${this.timeoutMs}ms`));
      });

      req.write(payload);
      req.end();
    });
  }

  getTools() {
    return this.tools;
  }

  /**
   * Invokes a tool on the external server.
   */
  async callTool(name, args = {}) {
    if (this.url) {
      return await this._sendHttpRequest('tools/call', { name, arguments: args });
    }
    return await this._sendRequest('tools/call', { name, arguments: args });
  }

  /**
   * Stops the external server process cleanly.
   */
  stop() {
    this.status = 'STOPPING';
    this._rejectAllPending(new Error('External server stopped by user'));
    if (this.rl) {
      try { this.rl.close(); } catch {}
      this.rl = null;
    }
    if (this.process) {
      try {
        if (this.process.stdin && !this.process.stdin.destroyed) {
          this.process.stdin.end();
          this.process.stdin.destroy();
        }
        if (this.process.stdout && !this.process.stdout.destroyed) {
          this.process.stdout.destroy();
        }
        this.process.kill('SIGTERM');
      } catch {
        // Ignored
      }
      this.process = null;
    }
    this.status = 'STOPPED';
    this.isReady = false;
  }
}

module.exports = {
  ExternalProcessServer,
  tokenizeCommand
};
