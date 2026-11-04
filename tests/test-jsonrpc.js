/**
 * AegisMCP - RFC 7693 & JSON-RPC 2.0 Protocol Engine Unit Tests
 */

'use strict';

const assert = require('node:assert');
const {
  PROTOCOL_VERSION,
  ERROR_CODES,
  createRequest,
  createResponse,
  createError,
  createNotification,
  validateMessage,
  parseMessage,
  formatMessage
} = require('../src/protocol/jsonrpc');

async function runJsonRpcTests() {
  console.log('🧪 Testing RFC 7693 & JSON-RPC 2.0 Protocol Engine...');

  // 1. Protocol Version and Standard Error Codes
  assert.strictEqual(PROTOCOL_VERSION, '2024-11-05', 'PROTOCOL_VERSION must match MCP spec 2024-11-05');
  assert.strictEqual(ERROR_CODES.PARSE_ERROR, -32700);
  assert.strictEqual(ERROR_CODES.INVALID_REQUEST, -32600);
  assert.strictEqual(ERROR_CODES.METHOD_NOT_FOUND, -32601);
  assert.strictEqual(ERROR_CODES.INVALID_PARAMS, -32602);
  assert.strictEqual(ERROR_CODES.INTERNAL_ERROR, -32603);
  assert.strictEqual(ERROR_CODES.AEGIS_POLICY_VIOLATION, -32001);
  assert.strictEqual(ERROR_CODES.AEGIS_QUARANTINE_TRIGGERED, -32002);
  assert.strictEqual(ERROR_CODES.AEGIS_RATE_LIMIT_EXCEEDED, -32003);
  assert.strictEqual(ERROR_CODES.AEGIS_PAYLOAD_TOO_LARGE, -32004);
  assert.strictEqual(ERROR_CODES.AEGIS_TIMEOUT, -32005);

  // 2. createRequest Invariants
  const reqExplicitId = createRequest('tools/call', { name: 'test' }, 42);
  assert.strictEqual(reqExplicitId.jsonrpc, '2.0');
  assert.strictEqual(reqExplicitId.id, 42);
  assert.strictEqual(reqExplicitId.method, 'tools/call');
  assert.deepStrictEqual(reqExplicitId.params, { name: 'test' });

  const reqStringId = createRequest('ping', {}, 'custom-req-id');
  assert.strictEqual(reqStringId.id, 'custom-req-id');

  const reqAutoId = createRequest('initialize');
  assert.strictEqual(reqAutoId.jsonrpc, '2.0');
  assert.strictEqual(reqAutoId.method, 'initialize');
  assert.deepStrictEqual(reqAutoId.params, {});
  assert.strictEqual(typeof reqAutoId.id, 'string');
  assert.strictEqual(reqAutoId.id.length, 8);

  const reqAutoId2 = createRequest('initialize');
  assert.notStrictEqual(reqAutoId.id, reqAutoId2.id, 'Generated request IDs must be unique');

  // 3. createResponse Invariants
  const resExplicit = createResponse(1, { resultKey: 'value' });
  assert.strictEqual(resExplicit.jsonrpc, '2.0');
  assert.strictEqual(resExplicit.id, 1);
  assert.deepStrictEqual(resExplicit.result, { resultKey: 'value' });

  const resDefault = createResponse(2);
  assert.deepStrictEqual(resDefault.result, {}, 'Undefined result must default to empty object');

  // Falsy results must be preserved, not defaulted
  assert.strictEqual(createResponse(3, null).result, null);
  assert.strictEqual(createResponse(4, 0).result, 0);
  assert.strictEqual(createResponse(5, false).result, false);
  assert.strictEqual(createResponse(6, '').result, '');
  assert.deepStrictEqual(createResponse(7, []).result, []);

  // 4. createError Invariants
  const errNoData = createError(10, ERROR_CODES.METHOD_NOT_FOUND, 'Method not found');
  assert.strictEqual(errNoData.jsonrpc, '2.0');
  assert.strictEqual(errNoData.id, 10);
  assert.strictEqual(errNoData.error.code, -32601);
  assert.strictEqual(errNoData.error.message, 'Method not found');
  assert.strictEqual('data' in errNoData.error, false, 'Error without data must not have data key');

  const errWithData = createError(11, ERROR_CODES.AEGIS_POLICY_VIOLATION, 'Blocked', { ruleId: 'SEC-001' });
  assert.strictEqual(errWithData.id, 11);
  assert.deepStrictEqual(errWithData.error.data, { ruleId: 'SEC-001' });

  const errUndefinedId = createError(undefined, ERROR_CODES.PARSE_ERROR, 'Parse error');
  assert.strictEqual(errUndefinedId.id, null, 'Undefined id must default to null in JSON-RPC error');

  const errNullId = createError(null, ERROR_CODES.INVALID_REQUEST, 'Invalid request');
  assert.strictEqual(errNullId.id, null);

  // 5. createNotification Invariants
  const notif = createNotification('notifications/initialized', { client: 'Aegis' });
  assert.strictEqual(notif.jsonrpc, '2.0');
  assert.strictEqual(notif.method, 'notifications/initialized');
  assert.deepStrictEqual(notif.params, { client: 'Aegis' });
  assert.strictEqual('id' in notif, false, 'JSON-RPC Notification MUST NOT have an id property');

  const notifDefaultParams = createNotification('notifications/ping');
  assert.deepStrictEqual(notifDefaultParams.params, {});

  // 6. validateMessage Invariants
  // Non-objects and falsy values
  assert.strictEqual(validateMessage(null).valid, false);
  assert.strictEqual(validateMessage(undefined).valid, false);
  assert.strictEqual(validateMessage('string').valid, false);
  assert.strictEqual(validateMessage(12345).valid, false);
  assert.strictEqual(validateMessage(true).valid, false);

  // Invalid JSON-RPC version
  assert.strictEqual(validateMessage({}).valid, false);
  assert.strictEqual(validateMessage({ jsonrpc: '1.0', method: 'ping' }).valid, false);
  assert.strictEqual(validateMessage({ jsonrpc: 2.0, method: 'ping' }).valid, false);

  // Missing method or result/error
  assert.strictEqual(validateMessage({ jsonrpc: '2.0' }).valid, false);
  assert.strictEqual(validateMessage({ jsonrpc: '2.0', id: 1 }).valid, false);

  // Valid Request
  const validReq = validateMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.strictEqual(validReq.valid, true);
  assert.strictEqual(validReq.isRequest, true);
  assert.strictEqual(validReq.isResponse, false);
  assert.strictEqual(validReq.isNotification, false);

  // Valid Notification
  const validNotif = validateMessage({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.strictEqual(validNotif.valid, true);
  assert.strictEqual(validNotif.isRequest, true);
  assert.strictEqual(validNotif.isNotification, true);

  const validNotifNullId = validateMessage({ jsonrpc: '2.0', id: null, method: 'notifications/cancelled' });
  assert.strictEqual(validNotifNullId.valid, true);
  assert.strictEqual(validNotifNullId.isNotification, true);

  // Valid Response (result)
  const validRes = validateMessage({ jsonrpc: '2.0', id: 1, result: { tools: [] } });
  assert.strictEqual(validRes.valid, true);
  assert.strictEqual(validRes.isRequest, false);
  assert.strictEqual(validRes.isResponse, true);

  // Valid Response (error)
  const validErrRes = validateMessage({ jsonrpc: '2.0', id: 1, error: { code: -32600, message: 'Err' } });
  assert.strictEqual(validErrRes.valid, true);
  assert.strictEqual(validErrRes.isResponse, true);

  // 7. parseMessage Invariants
  // JSON Syntax Error -> -32700
  const parseMalformed = parseMessage('{ invalid json string');
  assert.strictEqual(parseMalformed.ok, false);
  assert.strictEqual(parseMalformed.error.error.code, ERROR_CODES.PARSE_ERROR);
  assert.strictEqual(parseMalformed.error.id, null);

  const parseEmpty = parseMessage('');
  assert.strictEqual(parseEmpty.ok, false);
  assert.strictEqual(parseEmpty.error.error.code, ERROR_CODES.PARSE_ERROR);

  // Invalid JSON-RPC Semantics -> -32600
  const parseInvalidVer = parseMessage('{"jsonrpc": "1.0", "method": "ping"}');
  assert.strictEqual(parseInvalidVer.ok, false);
  assert.strictEqual(parseInvalidVer.error.error.code, ERROR_CODES.INVALID_REQUEST);
  assert.strictEqual(parseInvalidVer.error.id, null);

  const parseMissingMethod = parseMessage('{"jsonrpc": "2.0"}');
  assert.strictEqual(parseMissingMethod.ok, false);
  assert.strictEqual(parseMissingMethod.error.error.code, ERROR_CODES.INVALID_REQUEST);

  const parsePrimitive = parseMessage('"some string"');
  assert.strictEqual(parsePrimitive.ok, false);
  assert.strictEqual(parsePrimitive.error.error.code, ERROR_CODES.INVALID_REQUEST);

  // Successful Parsing
  const parseOkReq = parseMessage('{"jsonrpc":"2.0","id":100,"method":"ping","params":{}}');
  assert.strictEqual(parseOkReq.ok, true);
  assert.strictEqual(parseOkReq.message.id, 100);
  assert.strictEqual(parseOkReq.message.method, 'ping');
  assert.strictEqual(parseOkReq.meta.isRequest, true);

  const parseOkNotif = parseMessage('{"jsonrpc":"2.0","method":"notifications/test"}');
  assert.strictEqual(parseOkNotif.ok, true);
  assert.strictEqual(parseOkNotif.meta.isNotification, true);

  const parseOkRes = parseMessage('{"jsonrpc":"2.0","id":100,"result":{"status":"ok"}}');
  assert.strictEqual(parseOkRes.ok, true);
  assert.strictEqual(parseOkRes.meta.isResponse, true);

  // 8. formatMessage Invariants
  const formatted = formatMessage({ jsonrpc: '2.0', id: 1, result: { done: true } });
  assert(formatted.endsWith('\n'), 'Formatted message must end with newline delimiter');
  assert.deepStrictEqual(JSON.parse(formatted.trim()), { jsonrpc: '2.0', id: 1, result: { done: true } });

  console.log('✅ RFC 7693 & JSON-RPC 2.0 Protocol Engine: All 8 test groups passed!');
}

module.exports = { runJsonRpcTests };

if (require.main === module) {
  runJsonRpcTests().catch(err => {
    console.error('JSON-RPC Test Suite Failed:', err);
    process.exit(1);
  });
}
