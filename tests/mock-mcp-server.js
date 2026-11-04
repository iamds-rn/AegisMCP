#!/usr/bin/env node

/**
 * Mock External MCP Server for Testing stdio Proxy Tunneling
 */

'use strict';

const readline = require('node:readline');

const rl = readline.createInterface({
  input: process.stdin,
  terminal: false
});

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const msg = JSON.parse(trimmed);
    const { id, method, params } = msg;

    if (method === 'initialize') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'mock-external-mcp', version: '2.1.0' }
        }
      }) + '\n');
      return;
    }

    if (method === 'ping') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: {}
      }) + '\n');
      return;
    }

    if (method === 'tools/list') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            {
              name: 'external_fetch_data',
              description: 'Fetches mock remote record',
              inputSchema: {
                type: 'object',
                properties: { query: { type: 'string' } },
                required: ['query']
              }
            }
          ]
        }
      }) + '\n');
      return;
    }

    if (method === 'tools/call') {
      const q = (params && params.arguments) ? params.arguments.query : 'default';
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: 'External query result: ' + q }]
        }
      }) + '\n');
      return;
    }
  } catch {
    // Ignore JSON errors
  }
});
