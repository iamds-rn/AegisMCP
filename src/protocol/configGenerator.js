/**
 * AegisMCP - AI Client Configuration Generator
 * Produces 1-click drop-in MCP client configurations for Claude Desktop, Cursor, Zed, and Windsurf.
 */

'use strict';

const path = require('node:path');

const BIN_PATH = path.resolve(__dirname, '../../bin/aegis-mcp.js');

class ClientConfigGenerator {
  /**
   * Generates configuration for specified client.
   *
   * @param {string} clientType - 'claude' | 'cursor' | 'zed' | 'windsurf' | 'http' | 'all'
   * @param {object} [options]
   * @param {string} [options.mode] - 'ENFORCE' | 'AUDIT_ONLY' | 'SANITIZE'
   * @param {string} [options.proxyCommand] - Optional upstream command to wrap (e.g. 'npx -y @modelcontextprotocol/server-filesystem /tmp')
   * @param {number} [options.port] - HTTP Gateway port (default: 3333)
   * @param {string} [options.binPath] - Path to aegis binary
   * @returns {object} Config object with client information and JSON snippets
   */
  static generate(clientType, options = {}) {
    if (!clientType || typeof clientType !== 'string') {
      throw new Error('Client type must be a valid string (e.g. claude, cursor, zed, windsurf, http, all).');
    }
    const mode = options.mode || 'ENFORCE';
    const proxyCmd = options.proxyCommand || null;
    const port = options.port || 3333;
    const bin = options.binPath || BIN_PATH;
    const env = (options.env && typeof options.env === 'object') ? options.env : null;

    const stdioArgs = proxyCmd
      ? [bin, '--proxy', proxyCmd, '--mode', mode]
      : [bin, '--stdio', '--mode', mode];

    const serverKey = proxyCmd ? 'aegis-shielded-upstream' : 'aegis-security-gateway';

    const configs = {
      claude: {
        name: 'Claude Desktop',
        configPath: '~/Library/Application Support/Claude/claude_desktop_config.json',
        windowsPath: '%APPDATA%\\Claude\\claude_desktop_config.json',
        snippet: {
          mcpServers: {
            [serverKey]: {
              command: 'node',
              args: stdioArgs,
              ...(env ? { env } : {})
            }
          }
        },
        instruction: 'Paste this snippet into your Claude Desktop configuration file and restart Claude.'
      },

      cursor: {
        name: 'Cursor IDE',
        configPath: '.cursor/mcp.json (or Cursor Settings > Features > MCP)',
        windowsPath: '.cursor\\mcp.json',
        snippet: {
          mcpServers: {
            [serverKey]: {
              command: 'node',
              args: stdioArgs,
              ...(env ? { env } : {})
            }
          }
        },
        instruction: 'Add this block to your .cursor/mcp.json or via Cursor Settings > Features > MCP Servers.'
      },

      zed: {
        name: 'Zed Editor',
        configPath: '~/.config/zed/settings.json',
        windowsPath: '%APPDATA%\\Zed\\settings.json',
        snippet: {
          context_servers: {
            [serverKey]: {
              command: {
                path: 'node',
                args: stdioArgs,
                ...(env ? { env } : {})
              }
            }
          }
        },
        instruction: 'Add to the context_servers property of your Zed settings.json.'
      },

      windsurf: {
        name: 'Windsurf / Codeium',
        configPath: '~/.codeium/windsurf/mcp_config.json',
        windowsPath: '%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json',
        snippet: {
          mcpServers: {
            [serverKey]: {
              command: 'node',
              args: stdioArgs,
              ...(env ? { env } : {})
            }
          }
        },
        instruction: 'Add to your Windsurf MCP configuration JSON file.'
      },

      http: {
        name: 'HTTP / SSE JSON-RPC Gateway',
        endpoint: `http://localhost:${port}/rpc`,
        healthEndpoint: `http://localhost:${port}/health`,
        snippet: {
          type: 'http-jsonrpc-2.0',
          url: `http://localhost:${port}/rpc`,
          headers: {
            'Content-Type': 'application/json'
          }
        },
        instruction: `Ensure Aegis is running (aegis-mcp --serve --port ${port}) and point HTTP clients to the RPC endpoint.`
      }
    };

    if (clientType === 'all') {
      return configs;
    }

    const selected = configs[clientType.toLowerCase()];
    if (!selected) {
      throw new Error(`Unsupported client "${clientType}". Supported: ${ClientConfigGenerator.getSupportedClients().join(', ')}.`);
    }

    return selected;
  }

  /**
   * Returns list of supported client types.
   * @returns {string[]}
   */
  static getSupportedClients() {
    return ['claude', 'cursor', 'zed', 'windsurf', 'http', 'all'];
  }
}

module.exports = {
  ClientConfigGenerator
};
