/**
 * AegisMCP - Milestone 1 Adversarial Stress Harness & Empirical Conformance Suite
 *
 * Targets:
 * 1. Notification Absorption Invariants (falsy IDs, empty strings, null IDs, burst notifications over HTTP/stdio).
 * 2. MCP Ping Probes & Discovery Stubs (rapid concurrent probes, parameter handling, schema conformance).
 * 3. Malformed JSON-RPC Frames & Parsing Attacks (truncated, malformed, invalid version, prototype pollution, deep nesting).
 * 4. Streaming DoS, Boundary Limits & Multi-byte UTF-8 Chunk Splitting.
 */

'use strict';

const assert = require('node:assert');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { AegisProxyServer } = require('../src/protocol/proxy');
const { parseMessage, createRequest, createNotification, ERROR_CODES } = require('../src/protocol/jsonrpc');

// Helper for raw HTTP requests
function sendRawHttpRequest({ port, path = '/rpc', method = 'POST', headers = {}, body = null, chunks = null }) {
  return new Promise((resolve, reject) => {
    const reqHeaders = Object.assign({}, headers);
    if (body !== null && typeof body === 'string' && reqHeaders['Content-Length'] === undefined) {
      reqHeaders['Content-Length'] = Buffer.byteLength(body);
    }
    if (!reqHeaders['Content-Type']) {
      reqHeaders['Content-Type'] = 'application/json';
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: reqHeaders
      },
      (res) => {
        const resChunks = [];
        res.on('data', (c) => resChunks.push(c));
        res.on('end', () => {
          const rawBuffer = Buffer.concat(resChunks);
          const rawString = rawBuffer.toString('utf8');
          let parsed = null;
          try {
            parsed = JSON.parse(rawString);
          } catch {
            // Non-JSON or empty response
          }
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            raw: rawString,
            data: parsed
          });
        });
      }
    );

    req.on('error', (err) => {
      // In DoS rejection tests, socket might be aborted by server
      resolve({ error: err, aborted: true });
    });

    if (chunks && Array.isArray(chunks)) {
      (async () => {
        for (const chunk of chunks) {
          req.write(chunk);
          // small tick to force separate TCP/HTTP framing
          await new Promise((r) => setTimeout(r, 5));
        }
        req.end();
      })().catch(reject);
    } else {
      if (body !== null) {
        req.write(body);
      }
      req.end();
    }
  });
}

async function runAdversarialM1Tests() {
  console.log('⚡ Starting Milestone 1 Adversarial Protocol Stress Harness...');

  // =========================================================================
  // SETUP TEST SERVER INSTANCES
  // =========================================================================
  const testServer = new AegisProxyServer();
  await testServer.startHttp(0);
  const serverPort = testServer.port;

  // Dedicated server with small body limit (32KB) for boundary stress
  const smallLimitServer = new AegisProxyServer({ maxBodySize: 32768 });
  await smallLimitServer.startHttp(0);
  const smallLimitPort = smallLimitServer.port;

  try {
    // =======================================================================
    // SUITE 1: ADVERSARIAL NOTIFICATION ABSORPTION & FALSY/EXOTIC IDS
    // =======================================================================
    console.log('  [Suite 1] Stress-Testing Notification Absorption & Falsy Request IDs...');

    // 1.1 Strict JSON-RPC 2.0 Notification (id omitted) -> HTTP 204
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/initialized',
          params: { clientInfo: { name: 'AdversarialTester', version: '1.0' } }
        })
      });
      assert.strictEqual(res.statusCode, 204, 'notifications/initialized must return HTTP 204');
      assert.strictEqual(res.raw, '', 'Notification response must have empty body');
    }

    // 1.2 $/ Progress notification -> HTTP 204
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: '$/progress',
          params: { progressToken: 123, progress: 50 }
        })
      });
      assert.strictEqual(res.statusCode, 204, '$/progress must return HTTP 204');
      assert.strictEqual(res.raw, '');
    }

    // 1.3 Unregistered custom notification (id omitted) -> MUST be absorbed silently (HTTP 204), NOT -32601
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'custom/random_unregistered_event',
          params: { foo: 'bar' }
        })
      });
      assert.strictEqual(res.statusCode, 204, 'Custom notifications without id must return HTTP 204');
      assert.strictEqual(res.raw, '');
    }

    // 1.4 Falsy ID: id === 0 (MUST NOT be treated as a notification! Must return HTTP 200 with id: 0)
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'ping',
          id: 0
        })
      });
      assert.strictEqual(res.statusCode, 200, 'ping with id: 0 must return HTTP 200');
      assert.strictEqual(res.data.id, 0, 'Response id must be number 0');
      assert.deepStrictEqual(res.data.result, {}, 'Response result must be {}');
    }

    // 1.5 Falsy ID: id === "" (empty string) (MUST NOT be treated as notification)
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'ping',
          id: ''
        })
      });
      assert.strictEqual(res.statusCode, 200, 'ping with id: "" must return HTTP 200');
      assert.strictEqual(res.data.id, '', 'Response id must be empty string');
      assert.deepStrictEqual(res.data.result, {});
    }

    // 1.6 Falsy ID: id === false (boolean)
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'ping',
          id: false
        })
      });
      assert.strictEqual(res.statusCode, 200, 'ping with id: false must return HTTP 200');
      assert.strictEqual(res.data.id, false, 'Response id must be boolean false');
      assert.deepStrictEqual(res.data.result, {});
    }

    // 1.7 Null ID: id === null in request (JSON-RPC 2.0 allows null id in requests)
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'ping',
          id: null
        })
      });
      assert.strictEqual(res.statusCode, 200, 'ping with id: null must return HTTP 200');
      assert.strictEqual(res.data.id, null, 'Response id must be null');
      assert.deepStrictEqual(res.data.result, {});
    }

    // 1.8 Exotic IDs: Float and large integer string
    {
      const resFloat = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 99.99 })
      });
      assert.strictEqual(resFloat.data.id, 99.99);

      const resLargeInt = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: '9007199254740993' })
      });
      assert.strictEqual(resLargeInt.data.id, '9007199254740993');
    }

    // 1.9 Notification method WITH an ID (buggy client sending notifications/initialized with id: 100)
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/initialized',
          id: 100,
          params: {}
        })
      });
      // Aegis absorbs notifications/* regardless of id presence
      assert.strictEqual(res.statusCode, 204, 'notifications/* with ID must be absorbed cleanly');
    }

    // 1.10 Burst notifications over HTTP (300 rapid concurrent notifications)
    {
      const burstSize = 300;
      const promises = [];
      for (let i = 0; i < burstSize; i++) {
        promises.push(
          sendRawHttpRequest({
            port: serverPort,
            body: JSON.stringify({
              jsonrpc: '2.0',
              method: i % 2 === 0 ? 'notifications/initialized' : 'custom/event',
              params: { seq: i, timestamp: Date.now() }
            })
          })
        );
      }
      const results = await Promise.all(promises);
      for (const r of results) {
        assert.strictEqual(r.statusCode, 204, 'Every burst notification must return HTTP 204');
      }
    }

    // 1.11 Stdio notification burst (500 notifications, assert 0 bytes stdout, then 1 ping)
    {
      const cliPath = path.resolve(__dirname, '../bin/aegis-mcp.js');
      const child = spawn(process.execPath, [cliPath, '--stdio'], {
        stdio: ['pipe', 'pipe', 'inherit']
      });

      let stdoutData = '';
      child.stdout.on('data', (c) => {
        stdoutData += c.toString('utf8');
      });

      // Write 500 notifications rapidly
      for (let i = 0; i < 500; i++) {
        const notif = JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/test',
          params: { idx: i }
        }) + '\n';
        child.stdin.write(notif);
      }

      // Allow 50ms for notifications to process
      await new Promise((r) => setTimeout(r, 60));
      assert.strictEqual(stdoutData, '', 'Stdio burst of notifications must produce exactly 0 bytes on stdout');

      // Now send a single ping
      const pingReq = JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 'probe-99' }) + '\n';
      child.stdin.write(pingReq);

      await new Promise((r) => setTimeout(r, 60));
      child.stdin.end();

      const lines = stdoutData.trim().split('\n').filter(Boolean);
      assert.strictEqual(lines.length, 1, 'Only the ping request should have produced an output line');
      const parsedPing = JSON.parse(lines[0]);
      assert.strictEqual(parsedPing.id, 'probe-99');
      assert.deepStrictEqual(parsedPing.result, {});
    }

    console.log('    ✔ Notification Absorption & Falsy IDs: All 11 checks PASSED.');

    // =======================================================================
    // SUITE 2: MCP PING PROBES & DISCOVERY STUBS STRESS
    // =======================================================================
    console.log('  [Suite 2] Stress-Testing Ping Probes & Discovery Stubs...');

    // 2.1 Concurrent Ping Storm (200 parallel requests)
    {
      const pingCount = 200;
      const pingPromises = [];
      for (let i = 0; i < pingCount; i++) {
        pingPromises.push(
          sendRawHttpRequest({
            port: serverPort,
            path: i % 2 === 0 ? '/rpc' : '/mcp',
            body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: `ping-${i}` })
          })
        );
      }
      const pingResults = await Promise.all(pingPromises);
      for (let i = 0; i < pingCount; i++) {
        const r = pingResults[i];
        assert.strictEqual(r.statusCode, 200);
        assert.strictEqual(r.data.id, `ping-${i}`);
        assert.deepStrictEqual(r.data.result, {});
      }
    }

    // 2.2 Ping with arbitrary parameters (must return {} and not fail)
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'ping',
          params: { nonce: 'crypto-random-nonce-12345', extra: [1, 2, 3] },
          id: 555
        })
      });
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.data.id, 555);
      assert.deepStrictEqual(res.data.result, {});
    }

    // 2.3 Discovery Stub: resources/list with various IDs
    {
      for (const testId of ['str-1', 42, 0, null, '']) {
        const res = await sendRawHttpRequest({
          port: serverPort,
          body: JSON.stringify({ jsonrpc: '2.0', method: 'resources/list', id: testId })
        });
        assert.strictEqual(res.statusCode, 200);
        assert.strictEqual(res.data.id, testId);
        assert.deepStrictEqual(res.data.result, { resources: [] });
      }
    }

    // 2.4 Discovery Stub: prompts/list with various IDs
    {
      for (const testId of ['p-1', 777, 0, null]) {
        const res = await sendRawHttpRequest({
          port: serverPort,
          body: JSON.stringify({ jsonrpc: '2.0', method: 'prompts/list', id: testId })
        });
        assert.strictEqual(res.statusCode, 200);
        assert.strictEqual(res.data.id, testId);
        assert.deepStrictEqual(res.data.result, { prompts: [] });
      }
    }

    // 2.5 Discovery Stub: tools/list verification
    {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 'tl-1' })
      });
      assert.strictEqual(res.statusCode, 200);
      assert(Array.isArray(res.data.result.tools), 'tools/list must return an array');
      assert(res.data.result.tools.length > 0, 'Virtual tools must be registered');
    }

    console.log('    ✔ Ping Probes & Discovery Stubs: All 5 checks PASSED.');

    // =======================================================================
    // SUITE 3: MALFORMED JSON-RPC FRAMES & PARSING ATTACKS
    // =======================================================================
    console.log('  [Suite 3] Adversarial Frame Parsing & Malformed Payloads...');

    // 3.1 Malformed JSON Syntax -> HTTP 400 with -32700 PARSE_ERROR
    const malformedSyntaxCases = [
      { name: 'Truncated JSON', raw: '{"jsonrpc": "2.0", "method": "pin' },
      { name: 'Trailing Comma', raw: '{"jsonrpc": "2.0", "method": "ping", "id": 1,}' },
      { name: 'Unquoted Key', raw: '{jsonrpc: "2.0", method: "ping", id: 1}' },
      { name: 'Single Quotes', raw: "{'jsonrpc': '2.0', 'method': 'ping', 'id': 1}" },
      { name: 'Empty String', raw: '' },
      { name: 'Whitespace Only', raw: '   \n\t  ' },
      { name: 'Null Byte in String', raw: '{"jsonrpc": "2.0", "method": "ping\u0000", "id": 1}' }
    ];

    for (const testCase of malformedSyntaxCases) {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: testCase.raw
      });
      if (testCase.name === 'Null Byte in String') {
        // Valid JSON with escaped null byte: should parse as JSON and succeed ping or fail method
        assert(res.statusCode === 200 || res.statusCode === 400);
      } else {
        assert.strictEqual(res.statusCode, 400, `Malformed syntax (${testCase.name}) must return HTTP 400`);
        assert.strictEqual(res.data.error.code, ERROR_CODES.PARSE_ERROR, `${testCase.name} must return code -32700`);
        assert.strictEqual(res.data.id, null);
      }
    }

    // 3.2 Invalid JSON-RPC 2.0 Semantics -> HTTP 400 with -32600 INVALID_REQUEST
    const invalidSemanticCases = [
      { name: 'String Primitive', raw: '"hello world"' },
      { name: 'Number Primitive', raw: '12345' },
      { name: 'Boolean Primitive', raw: 'true' },
      { name: 'Null Primitive', raw: 'null' },
      { name: 'Array Batch Request', raw: '[{"jsonrpc": "2.0", "method": "ping", "id": 1}]' },
      { name: 'Missing jsonrpc field', raw: '{"method": "ping", "id": 1}' },
      { name: 'Invalid jsonrpc version 1.0', raw: '{"jsonrpc": "1.0", "method": "ping", "id": 1}' },
      { name: 'Invalid jsonrpc version 3.0', raw: '{"jsonrpc": "3.0", "method": "ping", "id": 1}' },
      { name: 'Missing method and result/error', raw: '{"jsonrpc": "2.0", "id": 1}' },
      { name: 'Numeric method', raw: '{"jsonrpc": "2.0", "method": 12345, "id": 1}' },
      { name: 'Object method', raw: '{"jsonrpc": "2.0", "method": {}, "id": 1}' },
      { name: 'Array method', raw: '{"jsonrpc": "2.0", "method": ["ping"], "id": 1}' }
    ];

    for (const testCase of invalidSemanticCases) {
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: testCase.raw
      });
      assert.strictEqual(res.statusCode, 400, `Invalid semantic (${testCase.name}) must return HTTP 400`);
      assert.strictEqual(res.data.error.code, ERROR_CODES.INVALID_REQUEST, `${testCase.name} must return code -32600`);
      assert.strictEqual(res.data.id, null);
    }

    // 3.3 Deeply Nested JSON Object Structure (150 levels deep)
    {
      let deepObj = { leaf: 'test' };
      for (let i = 0; i < 150; i++) {
        deepObj = { nest: deepObj };
      }
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'ping',
          params: deepObj,
          id: 'deep-test'
        })
      });
      assert.strictEqual(res.statusCode, 200, 'Deeply nested object must not cause server crash');
      assert.strictEqual(res.data.id, 'deep-test');
    }

    // 3.4 Prototype Pollution Payload Injection
    {
      const pollutionPayload = JSON.stringify({
        jsonrpc: '2.0',
        method: 'ping',
        id: 'proto-pollute',
        __proto__: { pollutedByAttacker: true },
        params: {
          constructor: {
            prototype: { pollutedByConstructor: true }
          }
        }
      });
      const res = await sendRawHttpRequest({
        port: serverPort,
        body: pollutionPayload
      });
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(({}).pollutedByAttacker, undefined, 'Object.prototype must not be polluted');
      assert.strictEqual(({}).pollutedByConstructor, undefined, 'Constructor prototype must not be polluted');
    }

    console.log('    ✔ Malformed Frames & Parsing Attacks: All checks PASSED.');

    // =======================================================================
    // SUITE 4: STREAMING DOS, BOUNDARY SIZES & MULTI-BYTE UTF-8
    // =======================================================================
    console.log('  [Suite 4] Stress-Testing Streaming DoS, Boundary Limits & Split UTF-8...');

    // 4.1 Boundary Limits: Exact limit (32768 bytes) vs Limit + 1 (32769 bytes)
    {
      // Base frame header
      const prefix = '{"jsonrpc":"2.0","method":"ping","id":"b-1","params":{"pad":"';
      const suffix = '"}}';
      const overhead = Buffer.byteLength(prefix) + Buffer.byteLength(suffix);

      // 4.1.a Exact limit
      const exactPadding = 'A'.repeat(32768 - overhead);
      const exactBody = prefix + exactPadding + suffix;
      assert.strictEqual(Buffer.byteLength(exactBody), 32768);

      const resExact = await sendRawHttpRequest({
        port: smallLimitPort,
        body: exactBody
      });
      assert.strictEqual(resExact.statusCode, 200, 'Payload of exactly maxBodySize must be accepted');
      assert.strictEqual(resExact.data.id, 'b-1');

      // 4.1.b Limit + 1 byte (32769 bytes)
      const overPadding = 'A'.repeat(32769 - overhead);
      const overBody = prefix + overPadding + suffix;
      assert.strictEqual(Buffer.byteLength(overBody), 32769);

      const resOver = await sendRawHttpRequest({
        port: smallLimitPort,
        body: overBody
      });
      assert.strictEqual(resOver.statusCode, 413, 'Payload of maxBodySize + 1 must return HTTP 413');
      assert.strictEqual(resOver.data.error.code, ERROR_CODES.AEGIS_PAYLOAD_TOO_LARGE, 'Error code must be -32004');
    }

    // 4.2 Pre-Stream Fast-Fail via Content-Length header
    {
      const res = await sendRawHttpRequest({
        port: smallLimitPort,
        headers: { 'Content-Length': '10000000' }, // 10MB declared
        body: 'small-body-sent'
      });
      assert.strictEqual(res.statusCode, 413, 'Oversized declared Content-Length must fast-fail with HTTP 413');
      assert.strictEqual(res.data.error.code, ERROR_CODES.AEGIS_PAYLOAD_TOO_LARGE);
    }

    // 4.3 Chunked Streaming without Content-Length (streaming byte counter)
    {
      // Send 8 chunks of 5KB (40KB total > 32KB limit)
      const chunks = [];
      const chunk5k = Buffer.alloc(5120, 'X');
      for (let i = 0; i < 8; i++) {
        chunks.push(chunk5k);
      }

      const res = await sendRawHttpRequest({
        port: smallLimitPort,
        headers: { 'Transfer-Encoding': 'chunked' },
        chunks
      });
      assert(res.statusCode === 413 || res.aborted === true, 'Chunked overflow must be aborted or return 413');
      if (res.statusCode === 413) {
        assert.strictEqual(res.data.error.code, ERROR_CODES.AEGIS_PAYLOAD_TOO_LARGE);
      }
    }

    // 4.4 Corrupted / Negative Content-Length headers (RFC 9112 HTTP framing protection)
    {
      // Negative Content-Length: Node HTTP parser rejects invalid header with 400
      const resNeg = await sendRawHttpRequest({
        port: smallLimitPort,
        headers: { 'Content-Length': '-500' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 'neg-cl' })
      });
      assert.strictEqual(resNeg.statusCode, 400, 'Negative Content-Length must be rejected by HTTP parser with 400');

      // Garbage non-numeric Content-Length: Node HTTP parser rejects invalid header with 400
      const resGarbage = await sendRawHttpRequest({
        port: smallLimitPort,
        headers: { 'Content-Length': 'not_a_number' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 'garbage-cl' })
      });
      assert.strictEqual(resGarbage.statusCode, 400, 'Non-numeric Content-Length must be rejected by HTTP parser with 400');
    }

    // 4.5 Split Multi-Byte UTF-8 Streaming across Chunks
    {
      // U+1F6E1 (SHIELD) is 4 bytes in UTF-8: 0xF0 0x9F 0x9B 0xA1
      const emojiBuf = Buffer.from('\u{1F6E1}', 'utf8');
      assert.strictEqual(emojiBuf.length, 4);

      // Split the 4 bytes right in the middle: 2 bytes in chunk 1, 2 bytes in chunk 2
      const part1 = Buffer.concat([
        Buffer.from('{"jsonrpc":"2.0","method":"ping","id":"utf8-split","params":{"symbol":"', 'utf8'),
        emojiBuf.subarray(0, 2)
      ]);
      const part2 = Buffer.concat([
        emojiBuf.subarray(2),
        Buffer.from('"}}', 'utf8')
      ]);

      const res = await sendRawHttpRequest({
        port: serverPort,
        headers: {
          'Content-Length': Buffer.byteLength(part1) + Buffer.byteLength(part2)
        },
        chunks: [part1, part2]
      });

      assert.strictEqual(res.statusCode, 200, 'Split UTF-8 chunks must be reconstructed properly');
      assert.strictEqual(res.data.id, 'utf8-split');
    }

    // 4.6 Large notification exceeding body limit (> 32KB on smallLimitServer)
    {
      const largeNotif = JSON.stringify({
        jsonrpc: '2.0',
        method: 'notifications/test',
        params: { blob: 'Z'.repeat(40000) }
      });
      const res = await sendRawHttpRequest({
        port: smallLimitPort,
        body: largeNotif
      });
      assert.strictEqual(res.statusCode, 413, 'Oversized notification must be blocked by DoS limiter with HTTP 413');
      assert.strictEqual(res.data.error.code, ERROR_CODES.AEGIS_PAYLOAD_TOO_LARGE);
    }

    // 4.7 Gateway Health check after attacks
    {
      const healthRes = await sendRawHttpRequest({
        port: smallLimitPort,
        path: '/health',
        method: 'GET'
      });
      assert.strictEqual(healthRes.statusCode, 200);
      assert.strictEqual(healthRes.data.status, 'healthy');

      // Verify normal ping still works flawlessly
      const postAttackPing = await sendRawHttpRequest({
        port: smallLimitPort,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 'post-attack-probe' })
      });
      assert.strictEqual(postAttackPing.statusCode, 200);
      assert.strictEqual(postAttackPing.data.id, 'post-attack-probe');
    }

    console.log('    ✔ Streaming DoS, Boundary Limits & Split UTF-8: All checks PASSED.');

  } finally {
    if (testServer.httpServer) {
      await new Promise((r) => testServer.httpServer.close(r));
    }
    if (smallLimitServer.httpServer) {
      await new Promise((r) => smallLimitServer.httpServer.close(r));
    }
  }

  console.log('🛡️  All Milestone 1 Adversarial Challenges PASSED successfully!\n');
}

if (require.main === module) {
  runAdversarialM1Tests().catch((err) => {
    console.error('❌ Adversarial Challenge Failed:', err);
    process.exit(1);
  });
}

module.exports = { runAdversarialM1Tests };
