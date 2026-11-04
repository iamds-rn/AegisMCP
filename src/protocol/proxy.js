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

class AegisProxyServer {
  constructor(options = {}) {
    this.port = options.port || 3333;
    this.firewall = options.firewall || new FirewallEngine({ mode: MODES.ENFORCE });
    this.ledger = options.ledger || new AuditLedger();
    this.hub = options.hub || new VirtualHub();
    this.fuzzer = new ProtocolFuzzer();
    this.dagEngine = new DAGEngine({ firewall: this.firewall, ledger: this.ledger });
    this.httpServer = null;
    this.webDir = path.resolve(__dirname, '../../web');
  }

  /**
   * Processes a single JSON-RPC 2.0 request through the Aegis security pipeline.
   */
  async handleJsonRpc(reqObj) {
    const { id, method, params } = reqObj;

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
            version: '1.0.0'
          }
        },
        serverInfo: {
          name: 'AegisMCP-Proxy',
          version: '1.0.0'
        }
      });
    }

    // 2. Tools Discovery: tools/list
    if (method === 'tools/list') {
      const allTools = this.hub.listAllTools();
      return createResponse(id, {
        tools: allTools.map(t => ({
          name: `${t.serverName}__${t.name}`,
          description: `[${t.serverName}] ${t.description}`,
          inputSchema: t.inputSchema
        }))
      });
    }

    // 3. Tool Invocations: tools/call
    if (method === 'tools/call') {
      const rawName = params ? params.name : '';
      if (!rawName || typeof rawName !== 'string') {
        return createError(id, ERROR_CODES.INVALID_PARAMS, 'Parameter "name" is required and must be a string');
      }
      const toolArguments = (params && params.arguments && typeof params.arguments === 'object') ? params.arguments : {};

      // Parse server and tool names
      let serverName = 'virtual_filesystem';
      let toolName = rawName;
      if (rawName.includes('__')) {
        const parts = rawName.split('__');
        serverName = parts[0];
        toolName = parts[1];
      }

      // Step A: Audit Inbound Tool Call Attempt
      this.ledger.append('TOOL_CALL_ATTEMPT', {
        id,
        server: serverName,
        tool: toolName,
        arguments: toolArguments
      });

      // Step B: Zero-Trust Firewall Inspection
      const evalResult = this.firewall.evaluate(toolName, toolArguments, id);

      if (evalResult.blocked) {
        // Intercepted and quarantined
        this.ledger.append('FIREWALL_BLOCK', {
          id,
          server: serverName,
          tool: toolName,
          ruleId: evalResult.violation.ruleId,
          signature: evalResult.violation.signature,
          culprit: evalResult.violation.culprit
        });
        return evalResult.jsonrpcError;
      }

      const effectiveArgs = evalResult.sanitized ? evalResult.sanitizedParams : toolArguments;

      // Step C: Execution
      const startTime = Date.now();
      try {
        const result = await this.hub.executeTool(serverName, toolName, effectiveArgs);
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
        const durationMs = Date.now() - startTime;
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
   * Starts the stdio transport listener for CLI / local agent pairing.
   */
  startStdio() {
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

    this.ledger.append('SERVER_START_STDIO', { pid: process.pid });
  }

  /**
   * Starts the HTTP & Web Studio Gateway server.
   */
  startHttp(port = this.port) {
    return new Promise((resolve, reject) => {
      this.httpServer = http.createServer(async (req, res) => {
        // Enable CORS
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        if (req.method === 'OPTIONS') {
          res.writeHead(204);
          res.end();
          return;
        }

        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

        // Health endpoint
        if (url.pathname === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'healthy', version: '1.0.0', uptime: process.uptime() }));
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

        // JSON-RPC endpoint
        if (req.method === 'POST' && (url.pathname === '/rpc' || url.pathname === '/mcp')) {
          let body = '';
          req.on('data', chunk => { body += chunk; });
          req.on('end', async () => {
            const parsed = parseMessage(body);
            if (!parsed.ok) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(parsed.error));
              return;
            }
            const response = await this.handleJsonRpc(parsed.message);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(response));
          });
          return;
        }

        // Fuzzer API endpoint
        if (req.method === 'POST' && url.pathname === '/api/fuzz') {
          let body = '';
          req.on('data', chunk => { body += chunk; });
          req.on('end', async () => {
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
          });
          return;
        }

        // Pipeline Run endpoint
        if (req.method === 'POST' && url.pathname === '/api/pipeline/run') {
          let body = '';
          req.on('data', chunk => { body += chunk; });
          req.on('end', async () => {
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
          });
          return;
        }

        // Serve Static Web Studio assets strictly confined to webDir
        let safePath = '/index.html';
        try {
          const decoded = decodeURIComponent(url.pathname);
          const normalized = path.normalize(decoded).replace(/^(\.\.[\/\\])+/, '');
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
          filePath = path.join(this.webDir, 'index.html');
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
          fs.createReadStream(filePath).pipe(res);
          return;
        }

        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      });

      this.httpServer.listen(port, () => {
        this.ledger.append('SERVER_START_HTTP', { port });
        resolve(this.httpServer);
      });

      this.httpServer.on('error', reject);
    });
  }

  stop() {
    if (this.httpServer) {
      this.httpServer.close();
    }
  }
}

module.exports = {
  AegisProxyServer
};
