#!/usr/bin/env node
/**
 * Aeitron MCP Server — Stdio Command Line Runner
 * Can be configured directly in Claude Desktop (claude_desktop_config.json)
 * Authenticates environment credentials to pass verified authClaims to tools.
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAeitronMcpServer } from './server.js';
import { verifyAuthToken, AuthClaims } from './auth.js';
import { getConfig } from './config.js';

async function main(): Promise<void> {
  const config = getConfig();
  const rawKey = process.env.AEITRON_API_KEY || process.env.AEITRON_TOKEN;

  let authClaims: AuthClaims | undefined;

  if (rawKey) {
    const authResult = verifyAuthToken(rawKey, {
      isProduction: config.environment === 'production',
      allowSandbox: config.allowSandbox,
      jwtSecret: config.jwtSecret
    });

    if (!authResult.success) {
      process.stderr.write(`[aeitron-mcp] FATAL: Provided AEITRON_API_KEY failed authentication: ${authResult.error}\n`);
      process.exit(1);
    }

    authClaims = authResult.claims;
    process.stderr.write(`[aeitron-mcp] Authenticated STDIO session for tenant '${authClaims.tenantId}' (actor: ${authClaims.actorId})\n`);
  } else if (config.allowSandbox) {
    // Non-production local sandbox default for Claude Desktop local evaluation
    authClaims = {
      actorId: 'usr_local_dev',
      tenantId: 'tenant_local_workspace',
      tier: 'developer',
      scopes: [
        'account:read',
        'projects:read',
        'projects:write',
        'dns:read',
        'dns:write',
        'dns:write:delete',
        'usage:read'
      ],
      livemode: false
    };
    process.stderr.write('[aeitron-mcp] Notice: No AEITRON_API_KEY provided. Operating in local developer sandbox mode.\n');
  } else {
    // Fail-Closed in production
    process.stderr.write('[aeitron-mcp] FATAL: AEITRON_API_KEY environment variable is required to authenticate the STDIO MCP server in production.\n');
    process.exit(1);
  }

  const { server } = createAeitronMcpServer({
    config,
    authClaims
  });

  const transport = new StdioServerTransport();
  process.stderr.write('[aeitron-mcp] Initializing Aeitron MCP Server on stdio transport...\n');

  await server.connect(transport);
  process.stderr.write('[aeitron-mcp] Server connected and ready for tools/list and tools/call requests.\n');
}

main().catch((err) => {
  process.stderr.write(`[aeitron-mcp] Fatal error: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
