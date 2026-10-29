/**
 * Aeitron MCP Server — Factory & Initialization
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AeitronApiClient } from './client.js';
import { AuditLogger } from './audit.js';
import { registerAllTools } from './tools/index.js';
import { getConfig, McpServerConfig } from './config.js';
import { AuthClaims } from './auth.js';

export interface ServerOptions {
  config?: Partial<McpServerConfig>;
  client?: AeitronApiClient;
  audit?: AuditLogger;
  authClaims?: AuthClaims;
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
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {},
        prompts: {},
        resources: {}
      }
    }
  );

  // Register all tools onto the server with per-session auth claims
  registerAllTools(server, client, audit, options.authClaims);

  return { server, client, audit };
}
