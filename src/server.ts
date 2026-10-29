/**
 * Aeitron MCP Server — Factory & Initialization
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AeitronApiClient } from './client.js';
import { AuditLogger } from './audit.js';
import { registerAllTools } from './tools/index.js';
import { getConfig, McpServerConfig } from './config.js';

export interface ServerOptions {
  config?: Partial<McpServerConfig>;
  client?: AeitronApiClient;
  audit?: AuditLogger;
}

export function createAeitronMcpServer(options: ServerOptions = {}): {
  server: McpServer;
  client: AeitronApiClient;
  audit: AuditLogger;
} {
  const config = { ...getConfig(), ...options.config };
  const client = options.client || new AeitronApiClient(config);
  const audit = options.audit || new AuditLogger();

  const server = new McpServer(
    {
      name: 'aeitron-mcp-server',
      version: '0.1.0'
    },
    {
      capabilities: {
        tools: {},
        prompts: {},
        resources: {}
      }
    }
  );

  // Register all tools onto the server
  registerAllTools(server, client, audit);

  return { server, client, audit };
}

