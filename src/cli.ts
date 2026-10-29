#!/usr/bin/env node
/**
 * Aeitron MCP Server & Management CLI Runner
 * Supports STDIO MCP server execution and Operator Human Approval Workflows
 * (e.g., aeitron dns approve-deletion --request-id <req_id>).
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAeitronMcpServer } from './server.js';
import { verifyAuthToken, AuthClaims, authorizeDnsDeletionRequest, getPendingDnsDeletionRequest } from './auth.js';
import { getConfig } from './config.js';

interface ParsedCliArgs {
  command?: string;
  subcommand?: string;
  requestId?: string;
  token?: string;
  url?: string;
  help?: boolean;
}

export function parseCliArgs(args: string[]): ParsedCliArgs {
  const result: ParsedCliArgs = {};
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      result.help = true;
    } else if (arg === '--request-id' || arg === '-r') {
      result.requestId = args[++i];
    } else if (arg.startsWith('--request-id=')) {
      result.requestId = arg.slice('--request-id='.length);
    } else if (arg === '--token' || arg === '-t') {
      result.token = args[++i];
    } else if (arg.startsWith('--token=')) {
      result.token = arg.slice('--token='.length);
    } else if (arg === '--url' || arg === '-u') {
      result.url = args[++i];
    } else if (arg.startsWith('--url=')) {
      result.url = arg.slice('--url='.length);
    } else if (!arg.startsWith('-')) {
      positional.push(arg);
    }
  }

  if (positional.length > 0) result.command = positional[0];
  if (positional.length > 1) result.subcommand = positional[1];

  return result;
}

function printHelp(): void {
  process.stdout.write(`
Aeitron Infrastructure MCP Server & Operator CLI

USAGE:
  aeitron-mcp                                  Start MCP server on stdio transport (Claude Desktop / Agent mode)
  aeitron-mcp dns approve-deletion [OPTIONS]   Authorize a pending DNS deletion request as a human operator

OPTIONS FOR dns approve-deletion:
  --request-id, -r <ID>     Pending deletion request ID (e.g. del_req_abc123) (required)
  --token, -t <TOKEN>       Operator authentication token with scope 'dns:write:delete'
  --url, -u <URL>           Base URL of running Aeitron MCP HTTP server (optional)
  --help, -h                Show this help message

EXAMPLES:
  # Start STDIO MCP server for Claude Desktop:
  aeitron-mcp

  # Authorize destructive DNS record deletion:
  aeitron-mcp dns approve-deletion --request-id del_req_0192837465abc
\n`);
}

export async function handleDnsApproveDeletion(parsed: ParsedCliArgs): Promise<{ success: boolean; token?: string; error?: string }> {
  const config = getConfig();
  const requestId = parsed.requestId;

  if (!requestId) {
    process.stderr.write('[aeitron-mcp] ERROR: Missing required --request-id argument.\n');
    process.stderr.write('Usage: aeitron-mcp dns approve-deletion --request-id <req_id>\n');
    return { success: false, error: 'Missing required --request-id argument.' };
  }

  const rawToken = parsed.token || process.env.AEITRON_OPERATOR_TOKEN || process.env.AEITRON_API_KEY || process.env.AEITRON_TOKEN;

  // 1. If HTTP server URL is provided, attempt HTTP approval exclusively (no confusing local fallback)
  if (parsed.url) {
    if (!rawToken && !config.allowSandbox) {
      process.stderr.write('[aeitron-mcp] ERROR: Operator authentication token required for remote approval (--token or AEITRON_API_KEY).\n');
      return { success: false, error: 'Operator authentication token required for remote approval.' };
    }

    try {
      const targetUrl = `${parsed.url.replace(/\/+$/, '')}/v1/dns/approve-deletion`;
      const res = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${rawToken || 'atk_sandbox_dev_default_key'}`
        },
        body: JSON.stringify({ requestId })
      });

      const data = await res.json() as Record<string, unknown>;
      if (!res.ok) {
        process.stderr.write(`[aeitron-mcp] ERROR from HTTP server (${res.status}): ${data.error_description || data.error || 'Approval failed'}\n`);
        return { success: false, error: String(data.error_description || data.error) };
      }

      const dummyClaims: AuthClaims = {
        actorId: 'remote_operator',
        tenantId: String(data.tenantId || 'remote_tenant'),
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: config.environment === 'production'
      };
      printApprovalSuccess(data as { requestId: string; domain: string; recordId: string; approvalToken: string; expiresAt: number }, dummyClaims);
      return { success: true, token: String(data.approvalToken) };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[aeitron-mcp] ERROR: Remote approval server at ${parsed.url} unavailable; refusing local fallback. ${message}\n`);
      return { success: false, error: 'Remote approval failed. Check connectivity and retry against the same server.' };
    }
  }

  // 2. Direct authorization via persistent shared storage
  const pending = getPendingDnsDeletionRequest(requestId);
  if (!pending) {
    process.stderr.write(`[aeitron-mcp] ERROR: Pending deletion request '${requestId}' not found or expired.\n`);
    return { success: false, error: 'Pending deletion request not found or expired.' };
  }

  let operatorClaims: AuthClaims;
  if (rawToken) {
    const authResult = verifyAuthToken(rawToken, {
      isProduction: config.environment === 'production',
      allowSandbox: config.allowSandbox,
      jwtSecret: config.jwtSecret,
      requiredScopes: ['dns:delete:approve']
    });

    if (!authResult.success) {
      process.stderr.write(`[aeitron-mcp] ERROR: Operator authentication failed: ${authResult.error}\n`);
      return { success: false, error: authResult.error };
    }
    operatorClaims = authResult.claims;
  } else if (config.allowSandbox) {
    // In local sandbox mode, strictly bind the operator to the request's exact tenantId
    // Zero 'anonymous' bypass allowed.
    operatorClaims = {
      actorId: 'usr_operator_cli_dev',
      tenantId: pending.tenantId,
      tier: 'enterprise',
      scopes: ['dns:delete:approve'],
      livemode: false
    };
  } else {
    process.stderr.write('[aeitron-mcp] ERROR: Operator authentication token required (--token or AEITRON_API_KEY).\n');
    return { success: false, error: 'Operator authentication token required.' };
  }

  const result = authorizeDnsDeletionRequest(operatorClaims, requestId);
  if (!result.success) {
    process.stderr.write(`[aeitron-mcp] ERROR: Authorization rejected (${result.status}): ${result.error}\n`);
    return { success: false, error: result.error };
  }

  printApprovalSuccess({
    requestId: result.requestId,
    domain: result.domain,
    recordId: result.recordId,
    approvalToken: result.token,
    expiresAt: result.expiresAt
  }, operatorClaims);

  return { success: true, token: result.token };
}

function printApprovalSuccess(
  info: { requestId: string; domain: string; recordId: string; approvalToken: string; expiresAt: number },
  operator: AuthClaims
): void {
  process.stdout.write(`
============================================================
✓ DNS DELETION REQUEST AUTHORIZED BY HUMAN OPERATOR
============================================================
Request ID:      ${info.requestId}
Target Domain:   ${info.domain}
Target Record:   ${info.recordId}
Authorized By:   ${operator.actorId} (tenant: ${operator.tenantId})
Expires At:      ${new Date(info.expiresAt).toISOString()}

APPROVAL TOKEN (SINGLE-USE):
${info.approvalToken}

INSTRUCTIONS:
Provide this approvalToken to the 'delete_dns_record' MCP tool:
  approvalToken: "${info.approvalToken}"
  confirm: true
  dryRun: false
============================================================
\n`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const parsed = parseCliArgs(args);

  if (parsed.help) {
    printHelp();
    process.exit(0);
  }

  // Handle DNS approval CLI subcommand
  if (parsed.command === 'dns' && (parsed.subcommand === 'approve-deletion' || parsed.subcommand === 'approve')) {
    const outcome = await handleDnsApproveDeletion(parsed);
    process.exit(outcome.success ? 0 : 1);
  }

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

// Only execute main automatically if called directly as entrypoint
if (process.argv[1] && (process.argv[1].endsWith('cli.js') || process.argv[1].endsWith('cli.ts'))) {
  main().catch((err) => {
    process.stderr.write(`[aeitron-mcp] Fatal error: ${err instanceof Error ? err.stack : String(err)}\n`);
    process.exit(1);
  });
}
