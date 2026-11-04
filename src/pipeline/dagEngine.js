/**
 * AegisMCP - Visual Directed Acyclic Graph (DAG) Pipeline Engine
 * Multi-server tool orchestration, topological dependency resolution, and step execution.
 */

'use strict';

/**
 * Extracts dependency node IDs from template expressions like {{nodes.step1.output.value}}
 */
function extractDependencies(params) {
  const deps = new Set();
  const regex = /\{\{nodes\.([a-zA-Z0-9_-]+)\./g;
  const serialized = JSON.stringify(params);

  let match;
  while ((match = regex.exec(serialized)) !== null) {
    deps.add(match[1]);
  }
  return Array.from(deps);
}

/**
 * Resolves template string using execution context
 */
function interpolateValue(val, context) {
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
    return val.map(item => interpolateValue(item, context));
  } else if (val !== null && typeof val === 'object') {
    const res = {};
    for (const k of Object.keys(val)) {
      res[k] = interpolateValue(val[k], context);
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
   * Performs topological sort and cycle detection on nodes.
   *
   * @param {Array<object>} nodes
   * @returns {Array<object>} sorted nodes in execution order
   */
  resolveExecutionOrder(nodes) {
    const nodeMap = new Map(nodes.map(n => [n.id, n]));
    const inDegree = new Map();
    const adjList = new Map();

    for (const node of nodes) {
      inDegree.set(node.id, 0);
      adjList.set(node.id, []);
    }

    // Build graph edges from template dependencies
    for (const node of nodes) {
      const deps = extractDependencies(node.params || {});
      for (const depId of deps) {
        if (!nodeMap.has(depId)) {
          throw new Error(`Node "${node.id}" depends on unknown node "${depId}"`);
        }
        adjList.get(depId).push(node.id);
        inDegree.set(node.id, inDegree.get(node.id) + 1);
      }
    }

    // Kahn's algorithm for topological sort
    const queue = [];
    for (const [id, deg] of inDegree.entries()) {
      if (deg === 0) queue.push(id);
    }

    const order = [];
    while (queue.length > 0) {
      const curr = queue.shift();
      order.push(nodeMap.get(curr));

      for (const neighbor of adjList.get(curr)) {
        inDegree.set(neighbor, inDegree.get(neighbor) - 1);
        if (inDegree.get(neighbor) === 0) {
          queue.push(neighbor);
        }
      }
    }

    if (order.length !== nodes.length) {
      throw new Error('Cyclic dependency detected in DAG pipeline definition!');
    }

    return order;
  }

  /**
   * Executes a complete DAG pipeline.
   *
   * @param {object} pipeline - { id, name, nodes }
   * @param {Function} invokerFn - async (serverName, toolName, params) => result
   * @param {object} callbacks - { onNodeStart, onNodeFinish, onNodeError }
   */
  async executePipeline(pipeline, invokerFn, callbacks = {}) {
    const sortedNodes = this.resolveExecutionOrder(pipeline.nodes);
    const context = {
      pipelineId: pipeline.id,
      startedAt: new Date().toISOString(),
      nodes: {}
    };

    const executionLog = [];
    const startTime = Date.now();

    for (const node of sortedNodes) {
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
        // Resolve dynamic template parameters
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

        // Save into context for subsequent nodes
        context.nodes[node.id] = nodeRecord;

        // Log to tamper-evident audit ledger if available
        if (this.ledger) {
          this.ledger.append('PIPELINE_STEP_SUCCESS', {
            pipelineId: pipeline.id,
            nodeId: node.id,
            server: node.server,
            tool: node.tool,
            durationMs: nodeRecord.durationMs
          });
        }

        if (callbacks.onNodeFinish) {
          callbacks.onNodeFinish(nodeRecord);
        }
      } catch (err) {
        nodeRecord.status = 'FAILED';
        nodeRecord.error = err.message;
        nodeRecord.durationMs = Date.now() - nodeStart;
        context.nodes[node.id] = nodeRecord;

        if (this.ledger) {
          this.ledger.append('PIPELINE_STEP_FAILED', {
            pipelineId: pipeline.id,
            nodeId: node.id,
            server: node.server,
            tool: node.tool,
            error: err.message
          });
        }

        if (callbacks.onNodeError) {
          callbacks.onNodeError(nodeRecord, err);
        }

        executionLog.push(nodeRecord);
        throw new Error(`Pipeline halted at node "${node.id}": ${err.message}`);
      }

      executionLog.push(nodeRecord);
    }

    return {
      pipelineId: pipeline.id,
      status: 'COMPLETED',
      totalDurationMs: Date.now() - startTime,
      stepsExecuted: executionLog.length,
      executionLog,
      finalOutputs: context.nodes
    };
  }
}

module.exports = {
  DAGEngine,
  extractDependencies,
  interpolateValue
};
