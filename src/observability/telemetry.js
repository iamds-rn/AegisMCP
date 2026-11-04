/**
 * AegisMCP - OpenTelemetry & W3C Distributed Trace Context Engine
 * Zero external runtime dependencies (uses native node:crypto).
 * Implements W3C Trace Context (traceparent) standard for distributed agent tracing.
 */

'use strict';

const crypto = require('node:crypto');

function generateTraceId() {
  return crypto.randomBytes(16).toString('hex');
}

function generateSpanId() {
  return crypto.randomBytes(8).toString('hex');
}

/**
 * Parses W3C traceparent header: 00-{trace_id}-{parent_id}-{flags}
 */
function parseTraceparent(header) {
  if (typeof header !== 'string') return null;
  const match = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i.test(header.trim());
  if (!match) return null;

  const parts = header.trim().split('-');
  return {
    version: parts[0],
    traceId: parts[1].toLowerCase(),
    parentSpanId: parts[2].toLowerCase(),
    traceFlags: parts[3].toLowerCase()
  };
}

/**
 * Formats a W3C traceparent string
 */
function formatTraceparent(traceId, spanId, sampled = true) {
  const flags = sampled ? '01' : '00';
  return `00-${traceId}-${spanId}-${flags}`;
}

class Span {
  constructor(name, context = {}) {
    this.name = name;
    this.traceId = context.traceId || generateTraceId();
    this.spanId = generateSpanId();
    this.parentSpanId = context.parentSpanId || null;
    this.startTime = Date.now();
    this.endTime = null;
    this.durationMs = null;
    this.status = 'UNSET'; // UNSET, OK, ERROR
    this.statusMessage = null;
    this.attributes = { ...(context.attributes || {}) };
    this.events = [];
  }

  setAttribute(key, value) {
    this.attributes[key] = value;
    return this;
  }

  setAttributes(obj) {
    Object.assign(this.attributes, obj);
    return this;
  }

  addEvent(name, attributes = {}) {
    this.events.push({
      name,
      timestamp: Date.now(),
      attributes
    });
    return this;
  }

  setStatus(status, message = null) {
    this.status = status;
    if (message) this.statusMessage = message;
    return this;
  }

  recordException(err) {
    this.status = 'ERROR';
    this.statusMessage = err.message || String(err);
    this.addEvent('exception', {
      'exception.type': err.name || 'Error',
      'exception.message': err.message || String(err),
      'exception.stack': err.stack
    });
    return this;
  }

  end() {
    if (this.endTime === null) {
      this.endTime = Date.now();
      this.durationMs = this.endTime - this.startTime;
      if (this.status === 'UNSET') {
        this.status = 'OK';
      }
    }
    return this;
  }

  toTraceparent() {
    return formatTraceparent(this.traceId, this.spanId);
  }

  toJSON() {
    return {
      name: this.name,
      traceId: this.traceId,
      spanId: this.spanId,
      parentSpanId: this.parentSpanId,
      startTime: this.startTime,
      endTime: this.endTime,
      durationMs: this.durationMs,
      status: this.status,
      statusMessage: this.statusMessage,
      attributes: this.attributes,
      events: this.events
    };
  }
}

class TelemetryEngine {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.serviceName = options.serviceName || 'aegis-mcp-gateway';
    this.maxRecentSpans = options.maxRecentSpans || 1000;
    this.completedSpans = [];
  }

  /**
   * Starts a new distributed span, extracting parent context if provided
   */
  startSpan(name, parentContext = {}) {
    if (!this.enabled) {
      return new Span(name, parentContext);
    }

    let traceId = parentContext.traceId;
    let parentSpanId = parentContext.parentSpanId;

    if (parentContext.traceparent) {
      const parsed = parseTraceparent(parentContext.traceparent);
      if (parsed) {
        traceId = parsed.traceId;
        parentSpanId = parsed.parentSpanId;
      }
    }

    const span = new Span(name, {
      traceId,
      parentSpanId,
      attributes: {
        'service.name': this.serviceName,
        ...(parentContext.attributes || {})
      }
    });

    return span;
  }

  recordSpan(span) {
    if (!this.enabled || !span) return;
    span.end();
    this.completedSpans.push(span);
    if (this.completedSpans.length > this.maxRecentSpans) {
      this.completedSpans.shift();
    }
  }

  getRecentSpans(limit = 50) {
    return this.completedSpans.slice(-limit);
  }

  clear() {
    this.completedSpans = [];
  }
}

module.exports = {
  TelemetryEngine,
  Span,
  parseTraceparent,
  formatTraceparent,
  generateTraceId,
  generateSpanId
};
