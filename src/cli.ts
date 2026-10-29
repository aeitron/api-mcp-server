#!/usr/bin/env node
/**
 * Aeitron MCP Server — Stdio Command Line Runner
 * Can be configured directly in Claude Desktop (claude_desktop_config.json)
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAeitronMcpServer } from './server.js';

async function main(): Promise<void> {
  const { server } = createAeitronMcpServer();
  const transport = new StdioServerTransport();

  process.stderr.write('[aeitron-mcp] Initializing Aeitron MCP Server on stdio transport...\n');

  await server.connect(transport);

  process.stderr.write('[aeitron-mcp] Server connected and ready for tools/list and tools/call requests.\n');
}

main().catch((err) => {
  process.stderr.write(`[aeitron-mcp] Fatal error: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});

