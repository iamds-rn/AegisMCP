/**
 * AegisMCP - Visual Directed Acyclic Graph (DAG) Pipeline Engine
 * Multi-server tool orchestration, topological dependency resolution,
 * concurrent tier-based parallel execution (Promise.all), and cryptographic audit tracking.
 */

'use strict';

const crypto = require('node:crypto');

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/**
 * Deterministically serializes an object for canonical hashing.
 */
function canonicalStringify(obj, visited = new Set()) {
  if (obj === undefined) {
    return 'null';
  }
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (visited.has(obj)) {
    return '"[CIRCULAR]"';
  }
  visited.add(obj);

  if (Array.isArray(obj)) {
    const res = '[' + obj.map(item => canonicalStringify(item, visited)).join(',') + ']';
    visited.delete(obj);
    return res;
  }
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  const res = '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k], visited)).join(',') + '}';
  visited.delete(obj);
  return res;
}

/**
 * Extracts dependency node IDs from template expressions like {{nodes.step1.output.value}} or {{ nodes.step1 }}
 */
function extractDependencies(params) {
  if (!params) return [];
  const deps = new Set();
  const regex = /\{\{\s*nodes\.([a-zA-Z0-9_-]+)(?:\.[^}]+|\s*)?\}\}/g;

  let serialized;
  try {
    serialized = typeof params === 'string' ? params : JSON.stringify(params);
  } catch {
    return [];
  }
  if (!serialized) return [];

  let match;
  while ((match = regex.exec(serialized)) !== null) {
    deps.add(match[1]);
  }
  return Array.from(deps);
}

/**
 * Resolves template string using execution context with recursion depth limit
 */
function interpolateValue(val, context, depth = 0, maxDepth = 15) {
  if (depth > maxDepth) return val;
  if (typeof val === 'string') {
    return val.replace(/\{\{([^}]+)\}\}/g, (_, expression) => {
      const parts = expression.trim().split('.');
      if (parts[0] === 'system' && parts[1] === 'timestamp') {
        return new Date().toISOString();
      }
      if (parts[0] === 'nodes') {
        const nodeId = parts[1];
        const node = context.nodes[nodeId];
        if (!node) {
          throw new Error(`Unresolved template variable: nodes.${nodeId} does not exist in execution context.`);
        }
        let current = node;
        for (let i = 2; i < parts.length; i++) {
          if (current === undefined || current === null) break;
          current = current[parts[i]];
        }
        return current !== undefined ? (typeof current === 'object' ? JSON.stringify(current) : String(current)) : '';
      }
      return '';
    });
  } else if (Array.isArray(val)) {
    return val.map(item => interpolateValue(item, context, depth + 1, maxDepth));
  } else if (val !== null && typeof val === 'object') {
    const res = {};
    for (const k of Object.keys(val)) {
      res[k] = interpolateValue(val[k], context, depth + 1, maxDepth);
    }
    return res;
  }
  return val;
}

class DAGEngine {
  constructor(options = {}) {
    this.firewall = options.firewall || null;
    this.ledger = options.ledger || null;
  }

  /**
   * Partitions pipeline nodes into topological dependency tiers (layers).
   * Independent nodes within each tier can be executed concurrently in parallel.
   *
   * @param {Array<object>} nodes
   * @returns {Array<Array<object>>} Array of tiers (each tier is an array of independent nodes)
   */
  partitionIntoTiers(nodes) {
    if (!Array.isArray(nodes)) {
      throw new Error('Pipeline nodes must be an array.');
    }
    const nodeMap = new Map();
    for (const node of nodes) {
      if (!node || !node.id) {
        throw new Error('Every pipeline node must have a valid "id".');
      }
      if (nodeMap.has(node.id)) {
        throw new Error(`Duplicate node ID detected in pipeline: "${node.id}"`);
      }
      nodeMap.set(node.id, node);
    }

    const inDegree = new Map();
    const adjList = new Map();

    for (const node of nodes) {
      inDegree.set(node.id, 0);
      adjList.set(node.id, []);
    }

    // Build graph edges from template dependencies and explicit dependsOn/dependencies
    for (const node of nodes) {
      const templateDeps = extractDependencies(node.params || {});
      const explicitDeps = Array.isArray(node.dependsOn)
        ? node.dependsOn
        : (Array.isArray(node.dependencies) ? node.dependencies : []);
      const allDeps = new Set([...templateDeps, ...explicitDeps]);

      for (const depId of allDeps) {
        if (!nodeMap.has(depId)) {
          throw new Error(`Node "${node.id}" depends on unknown node "${depId}"`);
        }
        adjList.get(depId).push(node.id);
        inDegree.set(node.id, inDegree.get(node.id) + 1);
      }
    }

    // Kahn's algorithm partitioned by layer/tier
    let currentTierIds = [];
    for (const [id, deg] of inDegree.entries()) {
      if (deg === 0) currentTierIds.push(id);
    }
    currentTierIds.sort();

    const tiers = [];
    let visitedCount = 0;

    while (currentTierIds.length > 0) {
      const currentTierNodes = currentTierIds.map(id => nodeMap.get(id));
      tiers.push(currentTierNodes);
      visitedCount += currentTierIds.length;

      const nextTierIds = [];
      for (const currId of currentTierIds) {
        for (const neighbor of adjList.get(currId)) {
          inDegree.set(neighbor, inDegree.get(neighbor) - 1);
          if (inDegree.get(neighbor) === 0) {
            nextTierIds.push(neighbor);
          }
        }
      }
      nextTierIds.sort();
      currentTierIds = nextTierIds;
    }

    if (visitedCount !== nodes.length) {
      throw new Error('Cyclic dependency detected in DAG pipeline definition!');
    }

    return tiers;
  }

  /**
   * Performs topological sort and cycle detection on nodes.
   *
   * @param {Array<object>} nodes
   * @returns {Array<object>} sorted nodes in execution order
   */
  resolveExecutionOrder(nodes) {
    return this.partitionIntoTiers(nodes).flat();
  }

  /**
   * Executes a single pipeline node with template interpolation, firewall evaluation, and tool invocation.
   * @private
   */
  async _executeNode(node, pipeline, context, invokerFn, callbacks = {}) {
    const nodeRecord = {
      id: node.id,
      server: node.server,
      tool: node.tool,
      status: 'RUNNING',
      startedAt: new Date().toISOString(),
      durationMs: 0,
      resolvedParams: null,
      output: null,
      error: null
    };

    if (callbacks.onNodeStart) {
      callbacks.onNodeStart(nodeRecord);
    }

    const nodeStart = Date.now();

    try {
      // Resolve dynamic template parameters from context
      const resolvedParams = interpolateValue(node.params || {}, context);
      nodeRecord.resolvedParams = resolvedParams;

      // Evaluate firewall if present
      if (this.firewall) {
        const evalResult = this.firewall.evaluate(node.tool, resolvedParams);
        if (evalResult.blocked) {
          throw new Error(`Security Policy Blocked: [${evalResult.violation.ruleId}] ${evalResult.violation.signature}`);
        }
        if (evalResult.sanitized) {
          nodeRecord.resolvedParams = evalResult.sanitizedParams;
        }
      }

      // Execute tool via invoker
      const toolResult = await invokerFn(node.server, node.tool, nodeRecord.resolvedParams);

      // Check MCP protocol tool error flag (isError: true)
      if (toolResult && toolResult.isError) {
        const errorText = (toolResult.content && toolResult.content[0] && toolResult.content[0].text) || 'Tool reported execution error';
        throw new Error(`Tool execution error: ${errorText}`);
      }

      // Parse result content
      let parsedOutput = toolResult;
      if (toolResult && toolResult.content && toolResult.content[0] && toolResult.content[0].text) {
        try {
          parsedOutput = JSON.parse(toolResult.content[0].text);
        } catch {
          parsedOutput = { text: toolResult.content[0].text };
        }
      }

      nodeRecord.status = 'SUCCESS';
      nodeRecord.output = parsedOutput;
      nodeRecord.durationMs = Date.now() - nodeStart;

      // Save into context for subsequent nodes/tiers
      context.nodes[node.id] = nodeRecord;

      // Log to tamper-evident audit ledger if available
      if (this.ledger) {
        this.ledger.append('PIPELINE_STEP_SUCCESS', {
          pipelineId: context.pipelineId,
          nodeId: node.id,
          server: node.server,
          tool: node.tool,
          durationMs: nodeRecord.durationMs
        });
      }

      if (callbacks.onNodeFinish) {
        callbacks.onNodeFinish(nodeRecord);
      }

      return nodeRecord;
    } catch (err) {
      nodeRecord.status = 'FAILED';
      nodeRecord.error = err.message;
      nodeRecord.durationMs = Date.now() - nodeStart;
      context.nodes[node.id] = nodeRecord;

      if (this.ledger) {
        this.ledger.append('PIPELINE_STEP_FAILED', {
          pipelineId: context.pipelineId,
          nodeId: node.id,
          server: node.server,
          tool: node.tool,
          error: err.message
        });
      }

      if (callbacks.onNodeError) {
        callbacks.onNodeError(nodeRecord, err);
      }

      throw new Error(`Pipeline halted at node "${node.id}": ${err.message}`);
    }
  }

  /**
   * Executes a complete DAG pipeline using topological tier concurrency.
   * Independent nodes within each tier execute in parallel via Promise.all.
   * Wall-clock durations and cryptographic hashes per tier are recorded in the ledger.
   *
   * @param {object} pipeline - { id, name, nodes }
   * @param {Function} invokerFn - async (serverName, toolName, params) => result
   * @param {object} callbacks - { onNodeStart, onNodeFinish, onNodeError }
   */
  async executePipeline(pipeline, invokerFn, callbacks = {}) {
    if (!pipeline || !Array.isArray(pipeline.nodes)) {
      throw new Error('Pipeline definition must contain a "nodes" array.');
    }

    const pipelineId = pipeline.id || pipeline.name || 'unnamed-pipeline';
    const tiers = this.partitionIntoTiers(pipeline.nodes);
    const context = {
      pipelineId,
      startedAt: new Date().toISOString(),
      nodes: {}
    };

    const executionLog = [];
    const tierExecutions = [];
    const startTime = Date.now();

    for (let tierIndex = 0; tierIndex < tiers.length; tierIndex++) {
      const tier = tiers[tierIndex];
      const tierStartTime = Date.now();

      // Execute all independent nodes in this tier in parallel using Promise.all
      const tierRecords = await Promise.all(
        tier.map(node => this._executeNode(node, pipeline, context, invokerFn, callbacks))
      );

      const tierDurationMs = Date.now() - tierStartTime;

      // Compute cryptographic hash of the tier execution
      const tierHashPayload = canonicalStringify({
        tierIndex,
        pipelineId,
        nodes: tierRecords.map(r => ({
          id: r.id,
          server: r.server,
          tool: r.tool,
          status: r.status,
          output: r.output,
          durationMs: r.durationMs
        }))
      });
      const tierHash = sha256(tierHashPayload);

      const tierSummary = {
        tierIndex,
        nodeCount: tier.length,
        nodeIds: tier.map(n => n.id),
        durationMs: tierDurationMs,
        tierHash
      };
      tierExecutions.push(tierSummary);

      // Measure and record per-tier wall-clock durations and cryptographic hashes in the ledger
      if (this.ledger) {
        this.ledger.append('PIPELINE_TIER_COMPLETED', {
          pipelineId,
          tierIndex,
          nodeCount: tier.length,
          nodeIds: tier.map(n => n.id),
          durationMs: tierDurationMs,
          tierHash,
          timestamp: new Date().toISOString()
        });
      }

      for (const r of tierRecords) {
        executionLog.push(r);
      }
    }

    return {
      pipelineId,
      status: 'COMPLETED',
      totalDurationMs: Date.now() - startTime,
      stepsExecuted: executionLog.length,
      tiersExecuted: tiers.length,
      tierExecutions,
      executionLog,
      finalOutputs: context.nodes
    };
  }
}

module.exports = {
  DAGEngine,
  extractDependencies,
  interpolateValue,
  canonicalStringify,
  sha256
};
