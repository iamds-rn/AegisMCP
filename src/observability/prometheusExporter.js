/**
 * AegisMCP - Native Prometheus Metrics Exporter
 * Zero external runtime dependencies.
 * Formats operational metrics into Prometheus standard text exposition format.
 */

'use strict';

const BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5];

class PrometheusExporter {
  constructor() {
    this.counters = new Map(); // metricName+labels -> value
    this.gauges = new Map();   // metricName+labels -> value
    this.histograms = new Map(); // metricName+labels -> { count, sum, buckets: Map<number, count> }
  }

  _labelKey(labels) {
    if (!labels || Object.keys(labels).length === 0) return '';
    return Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${String(v).replace(/"/g, '\\"')}"`)
      .join(',');
  }

  incCounter(name, labels = {}, value = 1) {
    const lKey = this._labelKey(labels);
    const key = `${name}{${lKey}}`;
    this.counters.set(key, (this.counters.get(key) || 0) + value);
  }

  setGauge(name, labels = {}, value = 0) {
    const lKey = this._labelKey(labels);
    const key = `${name}{${lKey}}`;
    this.gauges.set(key, value);
  }

  observeDuration(name, labels = {}, durationSec = 0) {
    const lKey = this._labelKey(labels);
    const baseKey = `${name}{${lKey}}`;

    let hist = this.histograms.get(baseKey);
    if (!hist) {
      hist = {
        name,
        labels,
        count: 0,
        sum: 0,
        buckets: new Map(BUCKETS.map(b => [b, 0]))
      };
      this.histograms.set(baseKey, hist);
    }

    hist.count++;
    hist.sum += durationSec;

    for (const b of BUCKETS) {
      if (durationSec <= b) {
        hist.buckets.set(b, hist.buckets.get(b) + 1);
      }
    }
  }

  /**
   * Generates standard Prometheus exposition formatted string
   */
  exportMetrics({ ledger = null, approvalGate = null } = {}) {
    const lines = [];

    // System gauges
    const mem = process.memoryUsage();
    this.setGauge('aegis_memory_heap_bytes', {}, mem.heapUsed);
    this.setGauge('aegis_process_uptime_seconds', {}, process.uptime());

    if (ledger) {
      this.setGauge('aegis_ledger_block_height', {}, ledger.blocks ? ledger.blocks.length : 0);
    }

    if (approvalGate) {
      const pending = approvalGate.listPending ? approvalGate.listPending().length : 0;
      this.setGauge('aegis_pending_approvals', {}, pending);
    }

    // Export Gauges
    lines.push('# HELP aegis_memory_heap_bytes Process heap memory usage in bytes');
    lines.push('# TYPE aegis_memory_heap_bytes gauge');
    for (const [k, v] of this.gauges.entries()) {
      if (k.startsWith('aegis_memory_heap_bytes')) lines.push(`${k} ${v}`);
    }

    lines.push('# HELP aegis_ledger_block_height Current height of cryptographic audit ledger');
    lines.push('# TYPE aegis_ledger_block_height gauge');
    for (const [k, v] of this.gauges.entries()) {
      if (k.startsWith('aegis_ledger_block_height')) lines.push(`${k} ${v}`);
    }

    lines.push('# HELP aegis_pending_approvals Current pending human-in-the-loop approvals');
    lines.push('# TYPE aegis_pending_approvals gauge');
    for (const [k, v] of this.gauges.entries()) {
      if (k.startsWith('aegis_pending_approvals')) lines.push(`${k} ${v}`);
    }

    // Export Counters
    lines.push('# HELP aegis_requests_total Total number of incoming HTTP / JSON-RPC requests');
    lines.push('# TYPE aegis_requests_total counter');
    for (const [k, v] of this.counters.entries()) {
      if (k.startsWith('aegis_requests_total')) lines.push(`${k} ${v}`);
    }

    lines.push('# HELP aegis_firewall_blocks_total Total number of blocked requests by rule ID');
    lines.push('# TYPE aegis_firewall_blocks_total counter');
    for (const [k, v] of this.counters.entries()) {
      if (k.startsWith('aegis_firewall_blocks_total')) lines.push(`${k} ${v}`);
    }

    lines.push('# HELP aegis_tool_calls_total Total tool calls handled by gateway');
    lines.push('# TYPE aegis_tool_calls_total counter');
    for (const [k, v] of this.counters.entries()) {
      if (k.startsWith('aegis_tool_calls_total')) lines.push(`${k} ${v}`);
    }

    // Export Histograms
    if (this.histograms.size > 0) {
      lines.push('# HELP aegis_tool_duration_seconds Tool execution duration in seconds');
      lines.push('# TYPE aegis_tool_duration_seconds histogram');

      for (const hist of this.histograms.values()) {
        const lStr = this._labelKey(hist.labels);
        const prefix = lStr ? `${hist.name}{${lStr},` : `${hist.name}{`;

        for (const [le, count] of hist.buckets.entries()) {
          lines.push(`${prefix}le="${le}"} ${count}`);
        }
        lines.push(`${prefix}le="+Inf"} ${hist.count}`);
        lines.push(`${hist.name}_sum{${lStr}} ${hist.sum.toFixed(6)}`);
        lines.push(`${hist.name}_count{${lStr}} ${hist.count}`);
      }
    }

    return lines.join('\n') + '\n';
  }
}

module.exports = {
  PrometheusExporter,
  BUCKETS
};
