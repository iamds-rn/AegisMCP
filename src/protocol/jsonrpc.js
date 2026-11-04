/**
 * AegisMCP - JSON-RPC 2.0 Protocol Engine
 * Implements strict RFC 7693 / JSON-RPC 2.0 framing and MCP protocol specifications.
 */

'use strict';

const PROTOCOL_VERSION = '2024-11-05';

const ERROR_CODES = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  // Aegis-specific security and operational codes
  AEGIS_POLICY_VIOLATION: -32001,
  AEGIS_QUARANTINE_TRIGGERED: -32002,
  AEGIS_RATE_LIMIT_EXCEEDED: -32003,
  AEGIS_PAYLOAD_TOO_LARGE: -32004,
  AEGIS_TIMEOUT: -32005,
  AEGIS_EXECUTION_TIMEOUT: -32005,
  AEGIS_AWAITING_APPROVAL: -32006,
  AEGIS_ACCESS_DENIED: -32007,
  AEGIS_MTLS_UNAUTHORIZED: -32008,
  AEGIS_SANDBOX_MEMORY_EXCEEDED: -32009,
  AEGIS_SANDBOX_VIOLATION: -32010
};

/**
 * Creates a valid JSON-RPC 2.0 Request object
 */
function createRequest(method, params = {}, id = null) {
  return {
    jsonrpc: '2.0',
    id: id !== null ? id : Math.random().toString(36).substring(2, 10),
    method,
    params
  };
}

/**
 * Creates a valid JSON-RPC 2.0 Response object
 */
function createResponse(id, result) {
  return {
    jsonrpc: '2.0',
    id,
    result: result !== undefined ? result : {}
  };
}

/**
 * Creates a valid JSON-RPC 2.0 Error Response object
 */
function createError(id, code, message, data = null) {
  const errObj = {
    jsonrpc: '2.0',
    id: id !== undefined ? id : null,
    error: {
      code,
      message
    }
  };
  if (data !== null && data !== undefined) {
    errObj.error.data = data;
  }
  return errObj;
}

/**
 * Creates a JSON-RPC 2.0 Notification object (no id)
 */
function createNotification(method, params = {}) {
  return {
    jsonrpc: '2.0',
    method,
    params
  };
}

/**
 * Validates whether an incoming object is a conformant JSON-RPC 2.0 message
 */
function validateMessage(msg) {
  if (!msg || typeof msg !== 'object') {
    return { valid: false, error: 'Message must be an object' };
  }
  if (msg.jsonrpc !== '2.0') {
    return { valid: false, error: "Invalid jsonrpc version; expected '2.0'" };
  }
  const isRequest = typeof msg.method === 'string';
  const isResponse = Object.prototype.hasOwnProperty.call(msg, 'result') || Object.prototype.hasOwnProperty.call(msg, 'error');

  if (!isRequest && !isResponse) {
    return { valid: false, error: "Message must contain 'method' or 'result'/'error'" };
  }
  return { valid: true, isRequest, isResponse, isNotification: isRequest && (msg.id === undefined || msg.id === null) };
}

/**
 * Parses raw string input into a JSON-RPC 2.0 message with error handling
 */
function parseMessage(rawString) {
  try {
    const parsed = JSON.parse(rawString);
    const validation = validateMessage(parsed);
    if (!validation.valid) {
      return {
        ok: false,
        error: createError(null, ERROR_CODES.INVALID_REQUEST, validation.error)
      };
    }
    return { ok: true, message: parsed, meta: validation };
  } catch (err) {
    return {
      ok: false,
      error: createError(null, ERROR_CODES.PARSE_ERROR, `Parse error: ${err.message}`)
    };
  }
}

/**
 * Formats a message into a newline-delimited JSON string for stdio transports
 */
function formatMessage(msg) {
  return JSON.stringify(msg) + '\n';
}

module.exports = {
  PROTOCOL_VERSION,
  ERROR_CODES,
  createRequest,
  createResponse,
  createError,
  createNotification,
  validateMessage,
  parseMessage,
  formatMessage
};
