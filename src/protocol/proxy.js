/**
 * AegisMCP - MCP Protocol Proxy & Gateway Server
 * Intercepts JSON-RPC 2.0 frames over HTTP/SSE/stdio with active firewall inspection and audit chaining.
 */

'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const { PROTOCOL_VERSION, ERROR_CODES, createResponse, createError, parseMessage } = require('./jsonrpc');
const { FirewallEngine, MODES } = require('../firewall/engine');
const { AuditLedger } = require('../ledger/auditLedger');
const { VirtualHub } = require('../servers/virtualHub');
const { ProtocolFuzzer } = require('../fuzzer/fuzzer');
const { DAGEngine } = require('../pipeline/dagEngine');
const { DynamicRuleSynthesizer } = require('../firewall/synthesizer');
const { ExploitPayloadGenerator } = require('../firewall/exploitGenerator');
const { ClientConfigGenerator } = require('./configGenerator');

const DEFAULT_MAX_BODY_SIZE = 1024 * 1024; // 1MB (1,048,576 bytes)

class AegisProxyServer {
  constructor(options = {}) {
    this.port = options.port || 3333;
    this.maxBodySize = typeof options.maxBodySize === 'number' && options.maxBodySize > 0
      ? options.maxBodySize
      : DEFAULT_MAX_BODY_SIZE;
    this.toolTimeoutMs = typeof options.toolTimeoutMs === 'number' && options.toolTimeoutMs > 0
      ? options.toolTimeoutMs
      : (typeof options.executionTimeoutMs === 'number' && options.executionTimeoutMs > 0
        ? options.executionTimeoutMs
        : (typeof options.timeoutMs === 'number' && options.timeoutMs > 0 ? options.timeoutMs : 30000));
    this.firewall = options.firewall || new FirewallEngine({
      mode: options.firewallMode || MODES.ENFORCE,
      rateLimit: options.rateLimit
    });
    this.ledger = options.ledger || new AuditLedger();
    this.hub = options.hub || new VirtualHub();
    this.fuzzer = new ProtocolFuzzer();
    this.synthesizer = new DynamicRuleSynthesizer();
    this.exploitGen = new ExploitPayloadGenerator({ synthesizer: this.synthesizer });
    this.dagEngine = new DAGEngine({ firewall: this.firewall, ledger: this.ledger });
    this.upstreamCommand = options.upstreamCommand || null;
    this.upstreamOptions = options.upstreamOptions || {};
    this.upstreamServer = null;
    this.httpServer = null;
    this.webDir = path.resolve(__dirname, '../../web');
  }

  setToolTimeout(timeoutMs) {
    if (typeof timeoutMs === 'number' && timeoutMs > 0) {
      this.toolTimeoutMs = timeoutMs;
    }
  }

  setRateLimit(config) {
    if (this.firewall) {
      this.firewall.setRateLimit(config);
    }
  }

  /**
   * Processes a single JSON-RPC 2.0 request through the Aegis security pipeline.
   */
  async handleJsonRpc(reqObj) {
    if (!reqObj || typeof reqObj !== 'object' || Array.isArray(reqObj)) {
      return createError(null, ERROR_CODES.INVALID_REQUEST, 'Invalid Request: expected a JSON-RPC request object');
    }

    const { id, method, params } = reqObj;

    // 0. Notification Absorption
    // JSON-RPC 2.0 notifications omit 'id', or methods prefixed with 'notifications/' or '$/'
    // Under RFC 7693 / JSON-RPC 2.0 Section 4.1, the server MUST NOT reply to notifications.
    const isNotification = id === undefined || (typeof method === 'string' && (method.startsWith('notifications/') || method.startsWith('$/')));
    if (isNotification) {
      if (method === 'notifications/initialized') {
        this.ledger.append('PROTOCOL_INITIALIZED', { clientParams: params });
      } else {
        this.ledger.append('NOTIFICATION_RECEIVED', { method, params });
      }
      return null;
    }

    // 1. Core MCP Protocol Handshake
    if (method === 'initialize') {
      this.ledger.append('PROTOCOL_HANDSHAKE', { clientParams: params });
      return createResponse(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          tools: { listChanged: true },
          resources: {},
          prompts: {},
          aegis: {
            firewall: true,
            auditLedger: true,
            fuzzer: true,
            version: '1.5.0'
          }
        },
        serverInfo: {
          name: 'AegisMCP-Proxy',
          version: '1.5.0'
        }
      });
    }

    // 2. Protocol Liveness Ping Probe
    if (method === 'ping') {
      return createResponse(id, {});
    }

    // 3. Resources Discovery Stub: resources/list
    if (method === 'resources/list') {
      return createResponse(id, { resources: [] });
    }

    // 4. Prompts Discovery Stub: prompts/list
    if (method === 'prompts/list') {
      return createResponse(id, { prompts: [] });
    }

    // 5. Tools Discovery: tools/list
    if (method === 'tools/list') {
      const allTools = this.hub.listAllTools();
      return createResponse(id, {
        tools: allTools.map(t => {
          const isUpstream = this.upstreamServer && t.serverName === this.upstreamServer.name;
          return {
            name: isUpstream ? t.name : `${t.serverName}__${t.name}`,
            description: `[${t.serverName}] ${t.description}`,
            inputSchema: t.inputSchema
          };
        })
      });
    }

    // 6. Tool Invocations: tools/call
    if (method === 'tools/call') {
      const rawName = params ? params.name : '';
      if (!rawName || typeof rawName !== 'string') {
        return createError(id, ERROR_CODES.INVALID_PARAMS, 'Parameter "name" is required and must be a string');
      }
      const toolArguments = (params && params.arguments && typeof params.arguments === 'object') ? params.arguments : {};

      // Parse server and tool names
      let serverName = null;
      let toolName = rawName;
      if (rawName.includes('__')) {
        const parts = rawName.split('__');
        serverName = parts[0];
        toolName = parts.slice(1).join('__');
      } else {
        if (this.upstreamServer) {
          serverName = this.upstreamServer.name;
        } else {
          const allTools = this.hub.listAllTools();
          const match = allTools.find(t => t.name === rawName);
          serverName = match ? match.serverName : 'virtual_filesystem';
        }
      }

      // Step A: Audit Inbound Tool Call Attempt
      this.ledger.append('TOOL_CALL_ATTEMPT', {
        id,
        server: serverName,
        tool: toolName,
        arguments: toolArguments
      });

      // Step B: Zero-Trust Firewall Inspection
      const rateLimitKey = (params && (params.clientId || params._clientId || params._key)) ||
                           (toolArguments && (toolArguments._clientId || toolArguments._key)) ||
                           toolName;
      const rateCost = (params && params._cost) || (toolArguments && toolArguments._cost) || 1;
      const evalResult = this.firewall.evaluate(toolName, toolArguments, id, {
        rateLimitKey,
        cost: rateCost
      });

      if (evalResult.blocked) {
        // Intercepted and quarantined
        this.ledger.append(evalResult.rateLimited ? 'RATE_LIMIT_EXCEEDED' : 'FIREWALL_BLOCK', {
          id,
          server: serverName,
          tool: toolName,
          ruleId: evalResult.violation.ruleId,
          signature: evalResult.violation.signature,
          culprit: evalResult.violation.culprit,
          retryAfterMs: evalResult.retryAfterMs
        });
        return evalResult.jsonrpcError;
      }

      const effectiveArgs = evalResult.sanitized ? evalResult.sanitizedParams : toolArguments;

      // Step C: Execution with Deterministic Timeout
      const startTime = Date.now();
      const executionTimeoutMs = Math.max(1,
        (toolArguments && (toolArguments._timeoutMs || toolArguments.timeoutMs)) ||
        (params && (params._timeoutMs || params.timeoutMs)) ||
        this.toolTimeoutMs ||
        30000
      );

      let timer = null;
      let didTimeout = false;
      const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
          didTimeout = true;
          const timeoutErr = new Error(`Tool "${toolName}" execution timed out after ${executionTimeoutMs}ms`);
          timeoutErr.code = 'AEGIS_TIMEOUT';
          timeoutErr.timeoutMs = executionTimeoutMs;
          reject(timeoutErr);
        }, executionTimeoutMs);
        if (typeof timer.unref === 'function') timer.unref();
      });

      try {
        const result = await Promise.race([
          this.hub.executeTool(serverName, toolName, effectiveArgs),
          timeoutPromise
        ]);
        if (timer) clearTimeout(timer);
        const durationMs = Date.now() - startTime;

        this.ledger.append('TOOL_CALL_SUCCESS', {
          id,
          server: serverName,
          tool: toolName,
          durationMs,
          sanitized: !!evalResult.sanitized
        });

        return createResponse(id, result);
      } catch (err) {
        if (timer) clearTimeout(timer);
        const durationMs = Date.now() - startTime;

        const isTimeout = didTimeout ||
                          err.code === 'AEGIS_TIMEOUT' ||
                          err.code === ERROR_CODES.AEGIS_TIMEOUT ||
                          err.code === 'ETIMEDOUT' ||
                          err.code === 'ESOCKETTIMEDOUT' ||
                          err.name === 'TimeoutError' ||
                          /timed?\s*out|timeout/i.test(err.message);

        if (isTimeout) {
          const timeoutVal = err.timeoutMs || executionTimeoutMs;
          this.ledger.append('TOOL_CALL_TIMEOUT', {
            id,
            server: serverName,
            tool: toolName,
            durationMs,
            timeoutMs: timeoutVal,
            error: err.message
          });

          return createError(
            id,
            ERROR_CODES.AEGIS_TIMEOUT,
            `Tool execution timed out after ${timeoutVal}ms: ${err.message}`,
            {
              tool: toolName,
              server: serverName,
              timeoutMs: timeoutVal,
              durationMs,
              recommendation: 'Increase execution timeout threshold or optimize tool operation.'
            }
          );
        }

        this.ledger.append('TOOL_CALL_ERROR', {
          id,
          server: serverName,
          tool: toolName,
          durationMs,
          error: err.message
        });

        return createError(id, ERROR_CODES.INTERNAL_ERROR, `Tool execution failed: ${err.message}`);
      }
    }

    // Unrecognized method
    return createError(id, ERROR_CODES.METHOD_NOT_FOUND, `Method not found: ${method}`);
  }

  /**
   * Reads and bounds incoming HTTP request bodies against streaming DoS.
   * Rejects oversized payloads with HTTP 413 and releases socket resources.
   * @param {http.IncomingMessage} req
   * @param {http.ServerResponse} res
   * @param {number} [maxLimit]
   * @returns {Promise<string|null>} Resolves with body string, or null if aborted/closed.
   */
  readRequestBody(req, res, maxLimit = this.maxBodySize) {
    return new Promise((resolve, reject) => {
      // 1. Fast-fail if Content-Length header exceeds limit
      const contentLengthHeader = req.headers['content-length'];
      if (contentLengthHeader !== undefined) {
        const declaredLength = parseInt(contentLengthHeader, 10);
        if (!Number.isNaN(declaredLength) && declaredLength > maxLimit) {
          req.resume(); // Discard unread bytes
          this._abortWith413(req, res, maxLimit, declaredLength);
          return resolve(null);
        }
      }

      let receivedBytes = 0;
      const chunks = [];
      let isAborted = false;

      const onData = (chunk) => {
        if (isAborted) return;
        receivedBytes += chunk.length;
        if (receivedBytes > maxLimit) {
          isAborted = true;
          req.pause();
          req.removeListener('data', onData);
          chunks.length = 0; // Release memory buffer immediately
          this._abortWith413(req, res, maxLimit, receivedBytes);
          resolve(null);
        } else {
          chunks.push(chunk);
        }
      };

      const onEnd = () => {
        if (isAborted) return;
        const fullBody = Buffer.concat(chunks, receivedBytes).toString('utf8');
        resolve(fullBody);
      };

      const onClose = () => {
        if (isAborted) return;
        isAborted = true;
        chunks.length = 0;
        resolve(null);
      };

      const onError = (err) => {
        if (isAborted) return;
        isAborted = true;
        chunks.length = 0;
        resolve(null);
      };

      req.on('data', onData);
      req.on('end', onEnd);
      req.on('close', onClose);
      req.on('error', onError);
    });
  }

  /**
   * Aborts an oversized request with HTTP 413 and schedules socket destruction.
   * @private
   */
  _abortWith413(req, res, limit, received) {
    if (res.headersSent) {
      if (req.socket && !req.socket.destroyed) req.socket.destroy();
      return;
    }

    const isRpc = req.url && (req.url.startsWith('/rpc') || req.url.startsWith('/mcp'));
    let responseBody;
    if (isRpc) {
      responseBody = JSON.stringify(
        createError(
          null,
          ERROR_CODES.AEGIS_PAYLOAD_TOO_LARGE,
          `Payload Too Large: request body exceeds maximum limit of ${limit} bytes`,
          { limit, received }
        )
      );
    } else {
      responseBody = JSON.stringify({
        error: 'Payload Too Large',
        code: ERROR_CODES.AEGIS_PAYLOAD_TOO_LARGE,
        message: `Request body exceeds maximum limit of ${limit} bytes`,
        limit,
        received
      });
    }

    res.writeHead(413, {
      'Content-Type': 'application/json',
      'Connection': 'close',
      'Access-Control-Allow-Origin': '*'
    });
    res.end(responseBody);

    const socket = req.socket;
    if (socket) {
      const fallbackTimer = setTimeout(() => {
        if (!socket.destroyed) socket.destroy();
      }, 1000);
      fallbackTimer.unref();

      res.once('finish', () => {
        clearTimeout(fallbackTimer);
        setTimeout(() => {
          if (!socket.destroyed) socket.destroy();
        }, 50).unref();
      });
    }
  }

  /**
   * Starts the stdio transport listener for CLI / local agent pairing.
   */
  async startStdio() {
    if (this.upstreamCommand) {
      try {
        this.upstreamServer = await this.hub.registerExternalServer({
          name: 'upstream',
          command: this.upstreamCommand,
          ledger: this.ledger,
          ...this.upstreamOptions
        });
        this.ledger.append('UPSTREAM_TUNNEL_INITIALIZED', {
          command: this.upstreamCommand,
          toolsCount: this.upstreamServer.getTools().length
        });
      } catch (err) {
        process.stderr.write(`[AegisMCP] Error connecting upstream server: ${err.message}\n`);
      }
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });

    rl.on('line', async (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      const parseResult = parseMessage(trimmed);
      if (!parseResult.ok) {
        process.stdout.write(JSON.stringify(parseResult.error) + '\n');
        return;
      }

      const response = await this.handleJsonRpc(parseResult.message);
      if (response) {
        process.stdout.write(JSON.stringify(response) + '\n');
      }
    });

    this.ledger.append('SERVER_START_STDIO', { pid: process.pid, proxiedUpstream: !!this.upstreamCommand });
  }

  /**
   * Starts the HTTP & Web Studio Gateway server.
   */
  startHttp(port = this.port) {
    return new Promise((resolve, reject) => {
      this.httpServer = http.createServer(async (req, res) => {
        // Prevent unhandled stream error crashes on client abrupt disconnect
        req.on('error', () => {});
        res.on('error', () => {});

        try {
          // Enable CORS
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
          res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

          if (req.method === 'OPTIONS') {
            res.writeHead(204);
            res.end();
            return;
          }

          let url;
          try {
            const rawHost = req.headers.host || 'localhost';
            const safeHost = rawHost.includes('[') && !rawHost.includes(']') ? 'localhost' : rawHost;
            url = new URL(req.url, `http://${safeHost}`);
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Bad Request: Malformed Host or URL' }));
            return;
          }

        // Health endpoint
        if (url.pathname === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'healthy', version: '1.5.0', uptime: process.uptime() }));
          return;
        }

        // Stats endpoint
        if (url.pathname === '/api/stats') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            firewall: this.firewall.getStats(),
            alerts: this.firewall.getRecentAlerts(),
            ledger: this.ledger.verify(),
            recentBlocks: this.ledger.getRecentBlocks(15)
          }));
          return;
        }

        // Ledger Verify endpoint
        if (url.pathname === '/api/ledger/verify') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(this.ledger.verify()));
          return;
        }

        // Ledger Proof Export endpoint
        if (url.pathname === '/api/ledger/proof') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(this.ledger.exportProof(), null, 2));
          return;
        }

        // Ledger Forensics endpoint (Tamper localization & blast radius)
        if (url.pathname === '/api/ledger/forensics') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(this.ledger.locateTamper()));
          return;
        }

        // Ledger Tamper Simulation endpoint
        if (req.method === 'POST' && url.pathname === '/api/ledger/tamper') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const { index, event } = JSON.parse(body || '{}');
            const targetIdx = index !== undefined ? parseInt(index, 10) : 1;
            this.ledger.tamper(targetIdx, event || { tampered: true, attacker: 'Adversary Simulation', timestamp: new Date().toISOString() });
            const forensics = this.ledger.locateTamper();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, tamperedIndex: targetIdx, forensics }));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Ledger Restore endpoint
        if (req.method === 'POST' && url.pathname === '/api/ledger/restore') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const { index } = JSON.parse(body || '{}');
            let result;
            if (index !== undefined) {
              const restored = this.ledger.restoreChain(parseInt(index, 10));
              result = { restoredIndex: index, success: restored, verification: this.ledger.verify() };
            } else {
              result = this.ledger.restoreAll();
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Historical Ledger Time-Travel Snapshot endpoint
        if (url.pathname.startsWith('/api/ledger/snapshot/')) {
          const idxStr = url.pathname.replace('/api/ledger/snapshot/', '');
          const idx = parseInt(idxStr, 10);
          try {
            const snap = this.ledger.getSnapshotAtBlock(idx);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(snap));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Servers List endpoint
        if (url.pathname === '/api/servers') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            servers: this.hub.listServers(),
            tools: this.hub.listAllTools()
          }));
          return;
        }

        // External Server Register endpoint
        if (req.method === 'POST' && url.pathname === '/api/servers/register') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const { name, command, args, url: serverUrl } = JSON.parse(body || '{}');
            if (!name || (!command && !serverUrl)) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Field "name" and either "command" or "url" are required.' }));
              return;
            }
            const server = await this.hub.registerExternalServer({
              name,
              command,
              args: Array.isArray(args) ? args : [],
              url: serverUrl
            });
            this.ledger.append('EXTERNAL_SERVER_REGISTERED', {
              name,
              command: command || serverUrl,
              toolsCount: server.getTools().length
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, server: { name, tools: server.getTools() } }));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Server Remove endpoint
        if (req.method === 'POST' && url.pathname === '/api/servers/remove') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const { name } = JSON.parse(body || '{}');
            const removed = this.hub.removeServer(name);
            this.ledger.append('SERVER_REMOVED', { name, success: removed });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: removed }));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Firewall Rate Limit Configuration endpoint
        if (url.pathname === '/api/firewall/ratelimit') {
          if (req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(this.firewall.rateLimiter ? this.firewall.rateLimiter.getStats() : { enabled: false }));
            return;
          }
          if (req.method === 'POST') {
            const body = await this.readRequestBody(req, res);
            if (body === null) return;
            try {
              const config = JSON.parse(body || '{}');
              this.setRateLimit(config);
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: true, rateLimiter: this.firewall.rateLimiter.getStats() }));
            } catch (err) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: err.message }));
            }
            return;
          }
        }

        // Firewall Rules List endpoint
        if (url.pathname === '/api/firewall/rules') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            mode: this.firewall.mode,
            rules: this.firewall.getAllRules()
          }));
          return;
        }

        // Firewall Rule Toggle endpoint
        if (req.method === 'POST' && url.pathname === '/api/firewall/rules/toggle') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const { ruleId } = JSON.parse(body || '{}');
            const state = this.firewall.toggleRule(ruleId);
            this.ledger.append('FIREWALL_RULE_TOGGLED', { ruleId, enabled: state });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ruleId, enabled: state }));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Dynamic Rule Synthesizer endpoint
        if (req.method === 'POST' && url.pathname === '/api/firewall/synthesize') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const { tool, toolName, serverName, pattern, signatureName, severity } = JSON.parse(body || '{}');
            let targetTool = tool;
            if (!targetTool && toolName) {
              const sName = serverName || 'virtual_filesystem';
              const s = this.hub.getServer(sName);
              if (s) {
                targetTool = s.getTools().find(t => t.name === toolName);
              }
            }
            let rules = [];
            if (targetTool) {
              rules = this.synthesizer.synthesizeRulesForTool(targetTool);
            } else if (pattern) {
              const r = this.synthesizer.synthesizeRuleFromPattern(signatureName || 'Dynamic Custom Rule', pattern, severity || 'HIGH', toolName);
              rules = [r];
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ rules }));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Add Custom Rule endpoint
        if (req.method === 'POST' && url.pathname === '/api/firewall/rules/add') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const { id, name, severity, pattern, targetTool } = JSON.parse(body || '{}');
            const rule = this.synthesizer.synthesizeRuleFromPattern(name || 'Custom Dynamic Rule', pattern, severity || 'HIGH', targetTool);
            if (id) rule.id = id;
            this.firewall.addCustomRule(rule);
            this.ledger.append('CUSTOM_RULE_HOT_LOADED', { ruleId: rule.id, name: rule.name });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, rule: { id: rule.id, name: rule.name, severity: rule.severity } }));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Client Configuration Generator endpoint
        if (url.pathname.startsWith('/api/configs/')) {
          const client = url.pathname.replace('/api/configs/', '');
          try {
            const conf = ClientConfigGenerator.generate(client, {
              port: this.port,
              mode: this.firewall.mode,
              proxyCommand: this.upstreamCommand
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(conf, null, 2));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // JSON-RPC endpoint
        if (req.method === 'POST' && (url.pathname === '/rpc' || url.pathname === '/mcp')) {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;

          const parsed = parseMessage(body);
          if (!parsed.ok) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(parsed.error));
            return;
          }
          const response = await this.handleJsonRpc(parsed.message);
          if (response) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(response));
          } else {
            // Notification absorbed silently: HTTP 204 No Content per protocol
            res.writeHead(204);
            res.end();
          }
          return;
        }

        // Fuzzer API endpoint
        if (req.method === 'POST' && url.pathname === '/api/fuzz') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const data = JSON.parse(body || '{}');
            const { serverName = 'virtual_filesystem', toolName = 'read_file', withFirewall = true } = data;
            const server = this.hub.getServer(serverName);
            if (!server) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: `Server not found: ${serverName}` }));
              return;
            }
            const tool = server.getTools().find(t => t.name === toolName);
            if (!tool) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: `Tool not found: ${toolName}` }));
              return;
            }

            const invoker = (tName, payload) => server.callTool(tName, payload);
            const audit = await this.fuzzer.runAudit(tool, invoker, withFirewall ? this.firewall : null);

            this.ledger.append('FUZZ_AUDIT_COMPLETED', {
              server: serverName,
              tool: toolName,
              grade: audit.grade,
              scorePct: audit.scorePct,
              totalTests: audit.totalTests
            });

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(audit));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Exploit Payload Generator & Resilience Auditor API endpoint
        if (req.method === 'POST' && url.pathname === '/api/firewall/exploit-audit') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const data = JSON.parse(body || '{}');
            const { serverName = 'virtual_filesystem', toolName = 'read_file', withFirewall = true, autoHotReload = false } = data;
            const server = this.hub.getServer(serverName);
            if (!server) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: `Server not found: ${serverName}` }));
              return;
            }
            const tool = server.getTools().find(t => t.name === toolName);
            if (!tool) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: `Tool not found: ${toolName}` }));
              return;
            }

            const invoker = (tName, payload) => server.callTool(tName, payload);
            const audit = await this.exploitGen.runExploitAudit(tool, withFirewall ? this.firewall : null, invoker);

            if (autoHotReload && audit.autoSynthesizedRules && audit.autoSynthesizedRules.length > 0) {
              for (const rule of audit.autoSynthesizedRules) {
                this.firewall.addCustomRule(rule);
                this.ledger.append('CUSTOM_RULE_HOT_LOADED', { ruleId: rule.id, name: rule.name, source: 'EXPLOIT_AUDITOR' });
              }
            }

            this.ledger.append('EXPLOIT_AUDIT_COMPLETED', {
              server: serverName,
              tool: toolName,
              grade: audit.grade,
              defenseScorePct: audit.defenseScorePct,
              totalExploits: audit.totalExploits,
              vulnerableCount: audit.vulnerableCount
            });

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(audit));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Pipeline Run endpoint
        if (req.method === 'POST' && url.pathname === '/api/pipeline/run') {
          const body = await this.readRequestBody(req, res);
          if (body === null) return;
          try {
            const pipeline = JSON.parse(body || '{}');
            const invoker = (sName, tName, p) => this.hub.executeTool(sName, tName, p);
            const result = await this.dagEngine.executePipeline(pipeline, invoker);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }

        // Serve Static Web Studio assets strictly confined to webDir
        let safePath = '/index.html';
        try {
          const decoded = decodeURIComponent(url.pathname);
          if (decoded.includes('..') || url.pathname.includes('..')) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Forbidden');
            return;
          }
          const normalized = path.normalize(decoded);
          safePath = normalized === '/' ? '/index.html' : normalized;
        } catch {
          safePath = '/index.html';
        }

        let filePath = path.resolve(this.webDir, '.' + safePath);
        // Path Traversal Guard: ensure resolved path is strictly within webDir
        if (!filePath.startsWith(this.webDir + path.sep) && filePath !== path.join(this.webDir, 'index.html')) {
          res.writeHead(403, { 'Content-Type': 'text/plain' });
          res.end('Forbidden');
          return;
        }

        if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
          if (safePath === '/' || safePath === '/index.html') {
            filePath = path.join(this.webDir, 'index.html');
          } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not Found');
            return;
          }
        }

        if (fs.existsSync(filePath) && fs.statSync(filePath).isFile() && (filePath.startsWith(this.webDir + path.sep) || filePath === path.join(this.webDir, 'index.html'))) {
          const ext = path.extname(filePath);
          const mimeTypes = {
            '.html': 'text/html; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.js': 'application/javascript; charset=utf-8',
            '.json': 'application/json',
            '.png': 'image/png',
            '.svg': 'image/svg+xml'
          };
          res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
          const fileStream = fs.createReadStream(filePath);
          fileStream.on('error', () => {
            if (!res.headersSent) {
              res.writeHead(500, { 'Content-Type': 'text/plain' });
              res.end('Internal Server Error');
            }
          });
          fileStream.pipe(res);
          res.on('close', () => {
            fileStream.destroy();
          });
          return;
        }

        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      } catch (serverErr) {
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: serverErr.message || 'Internal Server Error' }));
        }
      }
    });

      this.httpServer.listen(port, () => {
        const assignedPort = this.httpServer.address().port;
        this.port = assignedPort;
        this.ledger.append('SERVER_START_HTTP', { port: assignedPort });
        resolve(this.httpServer);
      });

      this.httpServer.on('error', reject);
    });
  }

  stop() {
    if (this.httpServer) {
      this.httpServer.close();
    }
    if (this.hub) {
      this.hub.shutdownAll();
    }
  }
}

module.exports = {
  AegisProxyServer,
  DEFAULT_MAX_BODY_SIZE
};
