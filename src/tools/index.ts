/**
 * Aeitron MCP Server — Tool Registry Coordinator
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AeitronApiClient } from '../client.js';
import { AuditLogger } from '../audit.js';
import { registerAccountTools } from './account.js';
import { registerProjectTools } from './projects.js';
import { registerDnsTools } from './dns.js';
import { registerUsageTools } from './usage.js';

export function registerAllTools(
  server: McpServer,
  client: AeitronApiClient,
  audit: AuditLogger
): void {
  // Phase 1: Read-Only Tools
  registerAccountTools(server, client, audit);
  registerProjectTools(server, client, audit);
  registerDnsTools(server, client, audit);
  registerUsageTools(server, client, audit);
}

