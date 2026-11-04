/**
 * AegisMCP - External MCP Server Proxy & Supervised Process Manager
 * Spawns and manages external MCP server processes over stdio (or connects over HTTP/SSE),
 * dynamically discovers tools, provides crash-backoff supervision with exponential retry,
 * periodic heartbeat liveness probing, and tamper-evident ledger logging.
 */

'use strict';

const { spawn } = require('node:child_process');
const readline = require('node:readline');
const http = require('node:http');
const https = require('node:https');
const { EventEmitter } = require('node:events');
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
  let hasToken = false;

  for (let i = 0; i < cmdStr.length; i++) {
    const ch = cmdStr[i];

    if (escaped) {
      current += ch;
      escaped = false;
      hasToken = true;
      continue;
    }

    if (ch === '\\' && !inSingle) {
      escaped = true;
      continue;
    }

    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      hasToken = true;
      continue;
    }

    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      hasToken = true;
      continue;
    }

    if (/\s/.test(ch) && !inDouble && !inSingle) {
      if (hasToken || current.length > 0) {
        tokens.push(current);
        current = '';
        hasToken = false;
      }
    } else {
      current += ch;
      hasToken = true;
    }
  }

  if (hasToken || current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

class ExternalProcessServer extends EventEmitter {
  /**
   * @param {object} options
   * @param {string} options.name - Unique identifier name for this server (e.g. 'ext_filesystem')
   * @param {string} [options.command] - Shell command or binary to spawn (e.g. 'npx -y @modelcontextprotocol/server-filesystem /tmp')
   * @param {Array<string>} [options.args] - Process arguments
   * @param {string} [options.url] - Optional HTTP/SSE URL if connecting via network
   * @param {object} [options.env] - Environment variables
   * @param {number} [options.timeoutMs] - Request timeout (default: 15000ms)
   * @param {boolean} [options.autoRestart] - Whether to automatically restart on crash
   * @param {number} [options.maxRetries] - Max restart attempts (default: 3)
   * @param {number} [options.backoffBaseMs] - Base delay for exponential backoff in ms (default: 100)
   * @param {number} [options.maxBackoffMs] - Maximum backoff delay in ms (default: 5000)
   * @param {number} [options.heartbeatIntervalMs] - Liveness heartbeat probe interval in ms (0 = disabled)
   * @param {number} [options.pingIntervalMs] - Alias for heartbeatIntervalMs
   * @param {object} [options.ledger] - Optional AuditLedger instance for crash/recovery logging
   * @param {boolean} [options.logHeartbeats] - Whether to log every heartbeat to ledger (default: false)
   */
  constructor(options = {}) {
    super();
    if (!options.name) throw new Error('ExternalProcessServer requires a unique "name"');
    this.name = options.name;
    this.command = options.command || null;
    this.args = options.args || [];
    this.url = options.url || null;
    this.env = options.env || {};
    this.timeoutMs = options.timeoutMs || 15000;
    this.version = '1.0.0';
    this.description = options.description || `External MCP Server (${this.command || this.url})`;

    // Supervision & Crash-Recovery configuration
    this.maxRetries = typeof options.maxRestarts === 'number'
      ? options.maxRestarts
      : (typeof options.maxRetries === 'number' ? options.maxRetries : 3);
    this.maxRestarts = this.maxRetries;

    this.backoffBaseMs = typeof options.restartDelayMs === 'number'
      ? options.restartDelayMs
      : (typeof options.backoffBaseMs === 'number' ? options.backoffBaseMs : 100);
    this.restartDelayMs = this.backoffBaseMs;

    this.autoRestart = options.autoRestart !== undefined
      ? Boolean(options.autoRestart)
      : (this.maxRetries > 0);

    this.maxBackoffMs = typeof options.maxBackoffMs === 'number' ? options.maxBackoffMs : 5000;
    this.heartbeatIntervalMs = typeof options.heartbeatIntervalMs === 'number'
      ? options.heartbeatIntervalMs
      : (typeof options.pingIntervalMs === 'number' ? options.pingIntervalMs : 0);
    this.ledger = options.ledger || null;
    this.logHeartbeats = options.logHeartbeats === true;

    // Serialized write backpressure queue
    this._writePromiseChain = Promise.resolve();

    // Runtime state
    this.process = null;
    this.rl = null;
    this.isReady = false;
    this.tools = [];
    this.pendingRequests = new Map();
    this.nextRequestId = 1000;
    this.status = 'DISCONNECTED';

    // Supervision state
    this.retryCount = 0;
    this.isStopping = false;
    this.restartTimer = null;
    this.heartbeatTimer = null;
    this.lastHeartbeat = null;
    this.crashHistory = [];
    this._heartbeatBusy = false;
    this._killEscalationTimer = null;
  }

  setLedger(ledger) {
    this.ledger = ledger;
  }

  resetRetries() {
    this.retryCount = 0;
  }

  /**
   * Starts the external server process and performs the initial MCP handshake.
   */
  async start() {
    this.isStopping = false;
    if (this.status === 'CONNECTED' && this.isReady) {
      return this;
    }

    if (this.url) {
      return await this._initNetworkServer();
    }

    if (!this.command) {
      throw new Error(`ExternalProcessServer "${this.name}" has no command or url configured.`);
    }

    return await this._spawnAndHandshake();
  }

  /**
   * Internal helper to spawn child process, wire up stdio streams, and perform handshake.
   * @private
   */
  _spawnAndHandshake() {
    return new Promise((resolve, reject) => {
      let resolved = false;

      const cleanupPrevious = () => {
        if (this._killEscalationTimer) {
          clearTimeout(this._killEscalationTimer);
          this._killEscalationTimer = null;
        }
        if (this.rl) {
          try { this.rl.close(); } catch {}
          this.rl = null;
        }
        if (this.process) {
          try { this.process.removeAllListeners(); } catch {}
          try {
            if (this.process.stdin && !this.process.stdin.destroyed) {
              this.process.stdin.end();
              this.process.stdin.destroy();
            }
            if (this.process.stdout && !this.process.stdout.destroyed) {
              this.process.stdout.destroy();
            }
            if (this.process.stderr && !this.process.stderr.destroyed) {
              this.process.stderr.destroy();
            }
            this.process.kill('SIGTERM');
          } catch {}
          this.process = null;
        }
      };

      try {
        this.status = 'SPAWNING';
        cleanupPrevious();

        let cmd = this.command;
        let cmdArgs = [...this.args];
        if (cmd.includes(' ') || cmd.includes('"') || cmd.includes("'")) {
          const parts = tokenizeCommand(cmd);
          cmd = parts[0] || this.command;
          cmdArgs = [...parts.slice(1), ...cmdArgs];
        }

        this.process = spawn(cmd, cmdArgs, {
          env: { ...process.env, ...this.env },
          stdio: ['pipe', 'pipe', 'pipe']
        });

        // Defensive stream guard: suppress unhandled EPIPE/ERR_STREAM_DESTROYED when child exits
        if (this.process.stdin) {
          this.process.stdin.on('error', () => {});
        }

        this.rl = readline.createInterface({
          input: this.process.stdout,
          terminal: false
        });

        this.rl.on('line', (line) => {
          this._handleStdioLine(line);
        });

        this.process.stderr.on('data', (data) => {
          const str = data.toString().trim();
          if (str) {
            this.emit('stderr', str);
          }
        });

        this.process.on('error', (err) => {
          if (!resolved) {
            resolved = true;
            this.status = 'ERROR';
            this.isReady = false;
            this._rejectAllPending(new Error(`External process error: ${err.message}`));
            reject(err);
          } else {
            this._handleProcessError(err);
          }
        });

        this.process.on('exit', (code, signal) => {
          if (!resolved) {
            resolved = true;
            this.status = 'TERMINATED';
            this.isReady = false;
            this._rejectAllPending(new Error(`External process exited before handshake completed (code: ${code}, signal: ${signal})`));
            reject(new Error(`Process exited prematurely with code ${code}`));
          } else {
            this._handleProcessExit(code, signal);
          }
        });

        // Send MCP Protocol Handshake
        this._handshake()
          .then(() => {
            if (!resolved) {
              resolved = true;
              this.status = 'CONNECTED';
              this.isReady = true;
              this._startHeartbeat();
              this.emit('ready', { serverName: this.name });
              resolve(this);
            }
          })
          .catch((err) => {
            if (!resolved) {
              resolved = true;
              this.status = 'ERROR';
              this.isReady = false;
              this._rejectAllPending(err);
              reject(err);
            }
          });
      } catch (err) {
        if (!resolved) {
          resolved = true;
          this.status = 'ERROR';
          this.isReady = false;
          reject(err);
        }
      }
    });
  }

  /**
   * Handles unexpected child process termination and executes crash supervision.
   * @private
   */
  _handleProcessExit(code, signal) {
    this._stopHeartbeat();

    if (this.isStopping) {
      this.status = 'STOPPED';
      this.isReady = false;
      this._rejectAllPending(new Error(`External server stopped (code: ${code})`));
      return;
    }

    // Unexpected exit = CRASH
    this.status = 'CRASHED';
    this.isReady = false;
    this._rejectAllPending(new Error(`External process crashed with exit code ${code} (${signal})`));

    // Emit heartbeat failure if periodic heartbeat supervision was active
    if (this.heartbeatIntervalMs > 0) {
      if (this.ledger) {
        this.ledger.append('PROCESS_HEARTBEAT_FAILED', {
          serverName: this.name,
          error: `Process terminated (${signal || code})`,
          timestamp: new Date().toISOString()
        });
      }
      this.emit('heartbeatFailure', {
        serverName: this.name,
        error: `Process terminated (${signal || code})`
      });
    }

    const crashInfo = {
      serverName: this.name,
      command: this.command,
      exitCode: code !== null ? code : null,
      signal: signal || null,
      retryCount: this.retryCount,
      maxRetries: this.maxRetries,
      timestamp: new Date().toISOString()
    };
    this.crashHistory.push(crashInfo);

    // Ledger logging on crash
    if (this.ledger) {
      this.ledger.append('PROCESS_CRASH', crashInfo);
    }

    this.emit('crash', crashInfo);

    // Check supervision / automatic restart with exponential backoff
    if (this.autoRestart && this.retryCount < this.maxRetries) {
      const delay = Math.min(
        this.backoffBaseMs * Math.pow(2, this.retryCount),
        this.maxBackoffMs
      );
      const attempt = this.retryCount + 1;
      this.status = 'RECOVERING';
      this.emit('restarting', {
        serverName: this.name,
        attempt,
        delayMs: delay
      });

      this.restartTimer = setTimeout(async () => {
        this.restartTimer = null;
        if (this.isStopping) return;

        this.retryCount++;
        try {
          await this._spawnAndHandshake();

          const recoveryInfo = {
            serverName: this.name,
            retryCount: this.retryCount,
            maxRetries: this.maxRetries,
            recoveredAt: new Date().toISOString()
          };

          // Ledger logging on recovery
          if (this.ledger) {
            this.ledger.append('PROCESS_RECOVERY', recoveryInfo);
          }

          this.emit('recovery', recoveryInfo);
        } catch (restartErr) {
          if (this.retryCount < this.maxRetries && !this.isStopping) {
            this._handleProcessExit(null, 'RESTART_FAILED');
          } else {
            this.status = 'FAILED';
            if (this.ledger) {
              this.ledger.append('PROCESS_RESTART_EXHAUSTED', {
                serverName: this.name,
                retryCount: this.retryCount,
                maxRetries: this.maxRetries,
                error: restartErr.message,
                timestamp: new Date().toISOString()
              });
            }
            this.emit('restartExhausted', {
              serverName: this.name,
              retryCount: this.retryCount,
              maxRetries: this.maxRetries,
              error: restartErr.message
            });
          }
        }
      }, delay);
    } else {
      this.status = this.autoRestart ? 'FAILED' : 'TERMINATED';
      if (this.autoRestart && this.retryCount >= this.maxRetries) {
        if (this.ledger) {
          this.ledger.append('PROCESS_RESTART_EXHAUSTED', {
            serverName: this.name,
            retryCount: this.retryCount,
            maxRetries: this.maxRetries,
            timestamp: new Date().toISOString()
          });
        }
        this.emit('restartExhausted', {
          serverName: this.name,
          retryCount: this.retryCount,
          maxRetries: this.maxRetries
        });
      }
    }
  }

  /**
   * Handles process error event.
   * @private
   */
  _handleProcessError(err) {
    if (this.isStopping) return;
    this.emit('processError', { serverName: this.name, error: err.message });
  }

  /**
   * Look up and remove a pending request supporting string/number type coercion.
   * @private
   */
  _getPendingRequest(id) {
    if (this.pendingRequests.has(id)) {
      const entry = this.pendingRequests.get(id);
      this.pendingRequests.delete(id);
      return entry;
    }
    const numId = Number(id);
    if (!Number.isNaN(numId) && this.pendingRequests.has(numId)) {
      const entry = this.pendingRequests.get(numId);
      this.pendingRequests.delete(numId);
      return entry;
    }
    const strId = String(id);
    if (this.pendingRequests.has(strId)) {
      const entry = this.pendingRequests.get(strId);
      this.pendingRequests.delete(strId);
      return entry;
    }
    return null;
  }

  _handleStdioLine(line) {
    const trimmed = line.trim();
    if (!trimmed) return;

    const parsed = parseMessage(trimmed);
    if (!parsed.ok) return;

    const msg = parsed.message;
    // Check if this is a response to a pending request
    if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
      const pending = this._getPendingRequest(msg.id);
      if (pending) {
        clearTimeout(pending.timer);
        if (msg.error) {
          pending.reject(new Error(msg.error.message || `JSON-RPC error ${msg.error.code}`));
        } else {
          pending.resolve(msg.result);
        }
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
   * Writes data to process stdin with backpressure drain handling.
   * @private
   */
  async _writeToStdin(data) {
    if (!this.process || !this.process.stdin || this.process.stdin.destroyed) {
      throw new Error(`Server "${this.name}" stdin is not writable`);
    }

    const flushed = this.process.stdin.write(data);
    if (!flushed) {
      await new Promise((resolve, reject) => {
        const onDrain = () => { cleanup(); resolve(); };
        const onError = (err) => { cleanup(); reject(err); };
        const onClose = () => { cleanup(); resolve(); };
        const cleanup = () => {
          if (this.process && this.process.stdin) {
            this.process.stdin.removeListener('drain', onDrain);
            this.process.stdin.removeListener('error', onError);
            this.process.stdin.removeListener('close', onClose);
          }
        };
        this.process.stdin.once('drain', onDrain);
        this.process.stdin.once('error', onError);
        this.process.stdin.once('close', onClose);
      });
    }
  }

  /**
   * Sends a JSON-RPC request to the child process stdio and waits for the response.
   */
  _sendRequest(method, params = {}) {
    return new Promise((resolve, reject) => {
      if (!this.process || (this.status !== 'CONNECTED' && this.status !== 'SPAWNING')) {
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

      this._writePromiseChain = this._writePromiseChain
        .then(() => this._writeToStdin(JSON.stringify(req) + '\n'))
        .catch((err) => {
          clearTimeout(timer);
          this.pendingRequests.delete(id);
          reject(err);
        });
    });
  }

  /**
   * Sends a ping probe to verify external process responsiveness.
   */
  async ping(timeoutMs = 2000) {
    if (this.url) {
      return await this._sendHttpRequest('ping', {});
    }

    return new Promise((resolve, reject) => {
      if (!this.process || (this.status !== 'CONNECTED' && this.status !== 'SPAWNING')) {
        return reject(new Error(`Server "${this.name}" is not connected (status: ${this.status})`));
      }

      const id = ++this.nextRequestId;
      const req = createRequest('ping', {}, id);

      const timer = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Ping timeout (${timeoutMs}ms)`));
        }
      }, timeoutMs);

      this.pendingRequests.set(id, {
        resolve: (res) => resolve(res || {}),
        reject: (err) => {
          // If server responds with method not found (-32601), it is still alive and conforming to JSON-RPC
          if (err && err.message && (err.message.includes('-32601') || err.message.toLowerCase().includes('method not found'))) {
            resolve({ alive: true, note: 'Responded with method not found' });
          } else {
            reject(err);
          }
        },
        timer
      });

      this._writePromiseChain = this._writePromiseChain
        .then(() => this._writeToStdin(JSON.stringify(req) + '\n'))
        .catch((err) => {
          clearTimeout(timer);
          this.pendingRequests.delete(id);
          reject(err);
        });
    });
  }

  /**
   * Checks process liveness and health status.
   */
  async checkLiveness(timeoutMs = 2000) {
    const start = Date.now();
    try {
      if (this.url) {
        await this.ping(timeoutMs);
        return { alive: true, latencyMs: Date.now() - start };
      }
      if (this.status === 'STOPPED' || this.status === 'STOPPING') {
        return { alive: false, error: 'Server is stopped', latencyMs: 0 };
      }
      if (this.status === 'FAILED') {
        return { alive: false, error: 'Server has failed (retries exhausted)', latencyMs: 0 };
      }
      if (this.status === 'CRASHED' || this.status === 'RECOVERING') {
        return { alive: false, error: `Server is recovering (status: ${this.status})`, latencyMs: 0 };
      }
      if (!this.process) {
        return { alive: false, error: 'Process is not running', latencyMs: 0 };
      }
      if (this.process.killed || this.process.exitCode !== null) {
        return {
          alive: false,
          error: `Process terminated with code ${this.process.exitCode}`,
          latencyMs: 0
        };
      }
      if (this.isReady) {
        await this.ping(timeoutMs);
      }
      return {
        alive: true,
        pid: this.process.pid,
        latencyMs: Date.now() - start
      };
    } catch (err) {
      return {
        alive: false,
        error: err.message,
        latencyMs: Date.now() - start
      };
    }
  }

  /**
   * Starts periodic heartbeat liveness check if configured.
   * @private
   */
  _startHeartbeat() {
    this._stopHeartbeat();
    if (this.heartbeatIntervalMs <= 0) return;

    this.heartbeatTimer = setInterval(async () => {
      if (this.isStopping || !this.isReady || this._heartbeatBusy) return;
      this._heartbeatBusy = true;
      try {
        const check = await this.checkLiveness(Math.min(this.heartbeatIntervalMs, 2000));
        if (check.alive) {
          this.lastHeartbeat = Date.now();
          if (this.ledger && this.logHeartbeats) {
            this.ledger.append('PROCESS_HEARTBEAT', {
              serverName: this.name,
              latencyMs: check.latencyMs,
              timestamp: new Date().toISOString()
            });
          }
          this.emit('heartbeat', {
            serverName: this.name,
            timestamp: this.lastHeartbeat,
            latencyMs: check.latencyMs
          });
        } else {
          if (this.ledger) {
            this.ledger.append('PROCESS_HEARTBEAT_FAILED', {
              serverName: this.name,
              error: check.error,
              timestamp: new Date().toISOString()
            });
          }
          this.emit('heartbeatFailure', {
            serverName: this.name,
            error: check.error
          });
          if (this.autoRestart && !this.isStopping) {
            if (this.process) {
              const procToKill = this.process;
              try { procToKill.kill('SIGTERM'); } catch {}
              if (this._killEscalationTimer) clearTimeout(this._killEscalationTimer);
              this._killEscalationTimer = setTimeout(() => {
                this._killEscalationTimer = null;
                try {
                  if (procToKill && !procToKill.killed && procToKill.exitCode === null) {
                    procToKill.kill('SIGKILL');
                  }
                } catch {}
              }, 1000);
              if (this._killEscalationTimer.unref) this._killEscalationTimer.unref();
            }
          }
        }
      } catch (err) {
        if (this.ledger) {
          this.ledger.append('PROCESS_HEARTBEAT_FAILED', {
            serverName: this.name,
            error: err.message,
            timestamp: new Date().toISOString()
          });
        }
        this.emit('heartbeatFailure', {
          serverName: this.name,
          error: err.message
        });
      } finally {
        this._heartbeatBusy = false;
      }
    }, this.heartbeatIntervalMs);

    if (this.heartbeatTimer.unref) {
      this.heartbeatTimer.unref();
    }
  }

  /**
   * Stops periodic heartbeat timer.
   * @private
   */
  _stopHeartbeat() {
    if (this._killEscalationTimer) {
      clearTimeout(this._killEscalationTimer);
      this._killEscalationTimer = null;
    }
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
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
      this._writePromiseChain = this._writePromiseChain
        .then(() => this._writeToStdin(JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/initialized',
          params: {}
        }) + '\n'))
        .catch(() => {});
      await this._writePromiseChain;
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
    this._startHeartbeat();
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
   * Waits for external server to become connected and ready, e.g. after a crash recovery backoff.
   * @param {number} [timeoutMs]
   */
  async waitForReady(timeoutMs = 15000) {
    if (this.isReady && this.status === 'CONNECTED') {
      return this;
    }
    if (this.status === 'STOPPED' || this.status === 'FAILED') {
      throw new Error(`Server "${this.name}" is not running (status: ${this.status})`);
    }

    return new Promise((resolve, reject) => {
      let timer = null;
      const onReady = () => {
        cleanup();
        resolve(this);
      };
      const onFail = (info) => {
        cleanup();
        reject(new Error(`Server "${this.name}" recovery failed: ${info ? (info.error || 'Retries exhausted') : 'failed'}`));
      };
      const onStop = () => {
        cleanup();
        reject(new Error(`Server "${this.name}" stopped`));
      };

      const cleanup = () => {
        if (timer) clearTimeout(timer);
        this.removeListener('ready', onReady);
        this.removeListener('recovery', onReady);
        this.removeListener('restartExhausted', onFail);
        this.removeListener('stopped', onStop);
      };

      timer = setTimeout(() => {
        cleanup();
        reject(new Error(`Timed out waiting for server "${this.name}" to become ready (${timeoutMs}ms)`));
      }, timeoutMs);
      if (timer.unref) timer.unref();

      this.once('ready', onReady);
      this.once('recovery', onReady);
      this.once('restartExhausted', onFail);
      this.once('stopped', onStop);
    });
  }

  /**
   * Invokes a tool on the external server.
   */
  async callTool(name, args = {}) {
    if (this.url) {
      return await this._sendHttpRequest('tools/call', { name, arguments: args });
    }
    // If server is currently recovering or spawning, await readiness
    if (this.autoRestart && (this.status === 'RECOVERING' || this.status === 'SPAWNING' || this.status === 'CRASHED')) {
      await this.waitForReady(this.timeoutMs);
    }
    try {
      return await this._sendRequest('tools/call', { name, arguments: args });
    } catch (err) {
      // If process crashed while request was in flight, await recovery and retry once
      if (this.autoRestart && !this.isStopping && (this.status === 'RECOVERING' || this.status === 'CRASHED' || this.status === 'SPAWNING')) {
        await this.waitForReady(this.timeoutMs);
        return await this._sendRequest('tools/call', { name, arguments: args });
      }
      throw err;
    }
  }

  /**
   * Stops the external server process cleanly without triggering restart supervision.
   * Escalates to SIGKILL if the process does not terminate within gracePeriodMs.
   */
  stop(gracePeriodMs = 1000) {
    this.isStopping = true;
    this.status = 'STOPPING';
    this._stopHeartbeat();
    if (this._killEscalationTimer) {
      clearTimeout(this._killEscalationTimer);
      this._killEscalationTimer = null;
    }
    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }
    this._rejectAllPending(new Error('External server stopped by user'));
    if (this.rl) {
      try { this.rl.close(); } catch {}
      this.rl = null;
    }

    const proc = this.process;
    this.process = null;
    this.status = 'STOPPED';
    this.isReady = false;

    if (proc) {
      try {
        if (proc.stdin && !proc.stdin.destroyed) {
          proc.stdin.end();
          proc.stdin.destroy();
        }
        if (proc.stdout && !proc.stdout.destroyed) {
          proc.stdout.destroy();
        }
        if (proc.stderr && !proc.stderr.destroyed) {
          proc.stderr.destroy();
        }

        let killTimer = null;
        const onExit = () => {
          if (killTimer) clearTimeout(killTimer);
          try { proc.removeAllListeners(); } catch {}
        };
        proc.once('exit', onExit);

        proc.kill('SIGTERM');

        killTimer = setTimeout(() => {
          try {
            if (proc.exitCode === null) {
              proc.kill('SIGKILL');
            }
          } catch {}
        }, gracePeriodMs);

        if (killTimer.unref) killTimer.unref();
      } catch {
        // Ignored
      }
    }

    this.emit('stopped', { serverName: this.name });
  }
}

module.exports = {
  ExternalProcessServer,
  tokenizeCommand
};
