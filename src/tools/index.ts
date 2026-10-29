/**
 * Aeitron MCP Server — Tool Registry Coordinator
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AeitronApiClient } from '../client.js';
import { AuditLogger } from '../audit.js';
import { AuthClaims } from '../auth.js';
import { registerAccountTools } from './account.js';
import { registerProjectTools } from './projects.js';
import { registerDnsTools } from './dns.js';
import { registerUsageTools } from './usage.js';

export function registerAllTools(
  server: McpServer,
  client: AeitronApiClient,
  audit: AuditLogger,
  authClaims?: AuthClaims
): void {
  registerAccountTools(server, client, audit, authClaims);
  registerProjectTools(server, client, audit, authClaims);
  registerDnsTools(server, client, audit, authClaims);
  registerUsageTools(server, client, audit, authClaims);
}
