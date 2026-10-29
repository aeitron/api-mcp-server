/**
 * Aeitron MCP Tool — DNS Zone Management (get_dns_records, create_dns_record, delete_dns_record)
 * Enforces strict tool-level scope authorization, fail-closed safety confirmation,
 * dry-run support, and cryptographic human operator challenge verification.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AeitronApiClient, AeitronApiError } from '../client.js';
import { AuditLogger } from '../audit.js';
import {
  AuthClaims,
  checkToolAuthorization,
  checkDnsDeletionRateLimit,
  createDnsDeletionRequest,
  verifyAndConsumeDnsDeletionApproval,
  markDnsDeletionCompleted,
  markDnsDeletionFailed,
  markDnsDeletionExecutionUnknown
} from '../auth.js';

/**
 * Classifies whether an upstream deletion failure is ambiguous (network/gateway 5xx/timeout)
 * requiring execution_unknown state, or a confirmed definitive failure.
 */
export const isAmbiguousUpstreamFailure = (err: unknown): boolean => {
  if (err instanceof AeitronApiError) {
    return err.code === 'SERVICE_UNAVAILABLE' || err.status >= 500;
  }
  if (err instanceof Error) {
    return (
      (err as any).name === 'AbortError' ||
      /timed out|network error|fetch failed|ECONNRESET|EPIPE|socket/i.test(err.message)
    );
  }
  return false;
};

export function registerDnsTools(
  server: McpServer,
  client: AeitronApiClient,
  audit: AuditLogger,
  authClaims?: AuthClaims
): void {
  // 1. get_dns_records (Scope: dns:read)
  server.tool(
    'get_dns_records',
    'Fetch active DNS records (A, AAAA, CNAME, TXT, MX) for an authorized domain on the Aeitron edge network.',
    {
      domain: z
        .string()
        .min(3)
        .max(253)
        .regex(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Must be a valid fully-qualified domain name (e.g. "example.com")')
        .describe('Fully qualified domain name (e.g. "example.com" or "api.aeitron.com")')
    },
    async (args) => {
      const authCheck = checkToolAuthorization('get_dns_records', authClaims);
      if (!authCheck.authorized) {
        audit.logToolExecution('get_dns_records', args, 0, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, authCheck.error);
        return {
          isError: true,
          content: [{ type: 'text', text: `403 Forbidden: ${authCheck.error}` }]
        };
      }

      const startTime = Date.now();
      try {
        const { records } = await client.getDnsRecords(args.domain);
        const duration = Date.now() - startTime;

        audit.logToolExecution('get_dns_records', args, duration, true, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        });

        const rows = records.map(
          (r) => `| \`${r.type}\` | \`${r.name}\` | \`${r.value}\` | ${r.ttl}s | ${r.proxied ? '✓ Edge Proxied' : 'DNS Only'} | \`${r.id}\` |`
        );

        const markdownTable = [
          `### DNS Records for \`${args.domain}\` 🌐`,
          ``,
          `| Type | Name | Target / Value | TTL | Proxy Status | Record ID |`,
          `| :--- | :--- | :--- | :--- | :--- | :--- |`,
          ...rows,
          ``,
          `*Total active records: ${records.length}*`
        ].join('\n');

        return {
          content: [
            {
              type: 'text',
              text: markdownTable
            },
            {
              type: 'text',
              text: JSON.stringify({ domain: args.domain, records }, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const duration = Date.now() - startTime;
        audit.logToolExecution('get_dns_records', args, duration, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, err);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Failed to get DNS records for '${args.domain}': ${err instanceof Error ? err.message : String(err)}`
            }
          ]
        };
      }
    }
  );

  // 2. create_dns_record (Scope: dns:write)
  server.tool(
    'create_dns_record',
    'Add a new DNS routing record (A, AAAA, CNAME, TXT, MX) to an authorized domain zone.',
    {
      domain: z
        .string()
        .min(3)
        .max(253)
        .regex(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Must be a valid fully-qualified domain name')
        .describe('The domain zone to modify (e.g. "example.com")'),
      type: z
        .enum(['A', 'AAAA', 'CNAME', 'TXT', 'MX'])
        .describe('DNS record type'),
      name: z
        .string()
        .min(1)
        .max(253)
        .describe('Subdomain or name (e.g. "@" for root, "api", "www")'),
      value: z
        .string()
        .min(1)
        .describe('Target IP address, hostname, or text record content'),
      ttl: z
        .number()
        .int()
        .min(60)
        .max(86400)
        .default(300)
        .describe('Time-to-live in seconds (60-86400, default 300)'),
      proxied: z
        .boolean()
        .default(true)
        .describe('Whether edge proxy, DDoS protection, and TLS caching are enabled')
    },
    async (args) => {
      const authCheck = checkToolAuthorization('create_dns_record', authClaims);
      if (!authCheck.authorized) {
        audit.logToolExecution('create_dns_record', args, 0, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, authCheck.error);
        return {
          isError: true,
          content: [{ type: 'text', text: `403 Forbidden: ${authCheck.error}` }]
        };
      }

      const startTime = Date.now();
      try {
        const record = await client.createDnsRecord(args);
        const duration = Date.now() - startTime;

        audit.logToolExecution('create_dns_record', args, duration, true, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        });

        const summaryText = [
          `### DNS Record Created Successfully! 🌐`,
          `- **Domain:** \`${record.domain}\``,
          `- **Record ID:** \`${record.id}\``,
          `- **Type:** \`${record.type}\``,
          `- **Name:** \`${record.name}\``,
          `- **Target/Value:** \`${record.value}\``,
          `- **TTL:** ${record.ttl}s | **Proxied:** ${record.proxied ? '✓ Yes' : 'No'}`
        ].join('\n');

        return {
          content: [
            {
              type: 'text',
              text: summaryText
            },
            {
              type: 'text',
              text: JSON.stringify(record, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const duration = Date.now() - startTime;
        audit.logToolExecution('create_dns_record', args, duration, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, err);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Failed to create DNS record: ${err instanceof Error ? err.message : String(err)}`
            }
          ]
        };
      }
    }
  );

  // 3. delete_dns_record (Scope: dns:write:delete - High-Risk Write with Safety Confirmation, Dry Run & Two-Step Challenge)
  server.tool(
    'delete_dns_record',
    'Permanently delete a DNS record from the domain zone. Requires scope dns:write:delete, explicit human operator confirmation, and valid cryptographic challenge approval token.',
    {
      domain: z
        .string()
        .min(3)
        .describe('The domain zone where the record is located'),
      recordId: z
        .string()
        .min(1)
        .describe('The unique record ID to delete (e.g. "rec_dns_cname_003")'),
      confirm: z
        .boolean()
        .default(false)
        .describe('Safety Confirmation: Must be explicitly true to confirm permanent deletion.'),
      dryRun: z
        .boolean()
        .default(false)
        .describe('Dry Run: If true, returns an impact preview and challenge token without performing deletion.'),
      approvalToken: z
        .string()
        .optional()
        .describe('Cryptographic approval challenge token issued by the server. Required to prevent AI prompt self-approval.')
    },
    async (args) => {
      // 1. Enforce high-risk delete scope
      const authCheck = checkToolAuthorization('delete_dns_record', authClaims);
      if (!authCheck.authorized) {
        audit.logToolExecution('delete_dns_record', args, 0, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, authCheck.error);
        return {
          isError: true,
          content: [{ type: 'text', text: `403 Forbidden: ${authCheck.error}` }]
        };
      }

      // 2. Validate tenant and actor identity (no anonymous fallback allowed for destructive mutations)
      const tenantId = authClaims?.tenantId;
      const actorId = authClaims?.actorId;
      if (
        !tenantId ||
        tenantId.trim().toLowerCase() === 'anonymous' ||
        !actorId ||
        !actorId.trim()
      ) {
        audit.logToolExecution('delete_dns_record', args, 0, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, 'Anonymous tenant or missing actor strictly prohibited from DNS deletion');
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: 'Forbidden: A valid authenticated tenant and actor are required for DNS deletion.'
            }
          ]
        };
      }

      // 2b. Rate Limiting Guard: Rate limit DNS deletion operations per tenant
      if (!checkDnsDeletionRateLimit(tenantId)) {
        audit.logToolExecution('delete_dns_record', args, 0, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, 'Rate limit exceeded on DNS deletion operations for this tenant');
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: '429 Too Many Requests: Rate limit exceeded on DNS deletion operations for this tenant.'
            }
          ]
        };
      }

      // Domain format validation
      const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
      if (!domainRegex.test(args.domain)) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Invalid domain format: '${args.domain}'. Must be a valid fully-qualified domain name (e.g., 'aeitron.com').`
            }
          ]
        };
      }

      // 3. Handle Dry Run Preview
      if (args.dryRun === true) {
        const req = createDnsDeletionRequest(tenantId, actorId, args.domain, args.recordId);
        audit.logToolExecution('delete_dns_record_preview', args, 0, true, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        });
        return {
          content: [
            {
              type: 'text',
              text: [
                `### ⚠️ DRY RUN PREVIEW: DNS Record Deletion`,
                `- **Domain Zone:** \`${args.domain}\``,
                `- **Target Record ID:** \`${args.recordId}\``,
                `- **Impact:** Deleting this record will stop resolving live traffic for this DNS name.`,
                `- **Deletion Request ID:** \`${req.requestId}\``,
                `- **Status:** Awaiting Human Operator Authorization`,
                `- **Expires:** In 5 minutes (${new Date(req.expiresAt).toISOString()})`,
                ``,
                `**HUMAN OPERATOR AUTHORIZATION REQUIRED:**`,
                `AI models are strictly prohibited from self-authorizing destructive resource deletions.`,
                `To execute this deletion, a verified human operator must authorize request ID \`${req.requestId}\` in the Aeitron Console or CLI:`,
                `  \`aeitron dns approve-deletion --request-id ${req.requestId}\``,
                `Then re-invoke \`delete_dns_record\` with \`approvalToken\`, \`confirm: true\`, and \`dryRun: false\`.`
              ].join('\n')
            }
          ]
        };
      }

      // 3. Safety Confirmation Guard: confirm must be explicitly true before consuming approval token
      if (args.confirm !== true) {
        audit.logToolExecution('delete_dns_record', args, 0, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, 'Confirmation rejected: confirm must be explicitly true');
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `⚠️ SAFETY GUARD: Permanent deletion requires explicit confirmation. Please specify "confirm: true" along with a valid approval token.`
            }
          ]
        };
      }

      // 4. Challenge Guard: Reject if no approval token is provided (prevents LLM self-authorization)
      if (!args.approvalToken) {
        const req = createDnsDeletionRequest(tenantId, actorId, args.domain, args.recordId);
        audit.logToolExecution('delete_dns_record', args, 0, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, 'Human operator challenge token required');
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: [
                `⚠️ SAFETY GUARD: Deleting a DNS record is a destructive action that can disrupt live production traffic.`,
                `AI models are strictly prohibited from self-authorizing destructive actions.`,
                ``,
                `Deletion Request ID generated: \`${req.requestId}\``,
                `Please ask the human operator to authorize this deletion via the Aeitron Console or CLI:`,
                `  \`aeitron dns approve-deletion --request-id ${req.requestId}\``,
                ``,
                `Once approved by the operator, re-invoke this tool with:`,
                `- \`approvalToken\`: "<one_time_token_from_operator>"`,
                `- \`confirm\`: true`,
                `- \`dryRun\`: false`,
                `*(Request expires in 5 minutes)*`
              ].join('\n')
            }
          ]
        };
      }

      // 5. Verify & Atomically Consume Cryptographic Challenge Approval Token (Replay Protected)
      const tokenVerification = verifyAndConsumeDnsDeletionApproval(args.approvalToken, tenantId, args.domain, args.recordId);
      if (!tokenVerification.valid) {
        audit.logToolExecution('delete_dns_record', args, 0, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, `Invalid approval token: ${tokenVerification.error}`);
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `403 Forbidden: Invalid or expired deletion approval token: ${tokenVerification.error}`
            }
          ]
        };
      }

      // 6. Perform Permanent Deletion with idempotencyKey binding
      const startTime = Date.now();
      try {
        const result = await client.deleteDnsRecord({
          domain: args.domain,
          recordId: args.recordId,
          idempotencyKey: tokenVerification.requestId
        });
        markDnsDeletionCompleted(tokenVerification.requestId);
        const duration = Date.now() - startTime;

        audit.logToolExecution('delete_dns_record', args, duration, true, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        });

        return {
          content: [
            {
              type: 'text',
              text: `### DNS Record Deleted Successfully 🗑️\n- **Domain:** \`${args.domain}\`\n- **Record ID:** \`${args.recordId}\`\n- **Status:** Record has been permanently removed from the edge zone.`
            },
            {
              type: 'text',
              text: JSON.stringify(result, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const ambiguous = isAmbiguousUpstreamFailure(err);

        if (ambiguous) {
          markDnsDeletionExecutionUnknown(tokenVerification.requestId, err instanceof Error ? err.message : String(err));
        } else {
          markDnsDeletionFailed(tokenVerification.requestId);
        }

        const duration = Date.now() - startTime;
        audit.logToolExecution('delete_dns_record', args, duration, false, {
          tenantId,
          actorId
        }, err);

        if (ambiguous) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: [
                  `⚠️ AMBIGUOUS UPSTREAM FAILURE: Network or gateway error occurred while deleting DNS record.`,
                  `- **Request ID:** \`${tokenVerification.requestId}\``,
                  `- **Status:** \`execution_unknown\` (state locked against race conditions)`,
                  `- **Impact:** The upstream DNS record deletion may have been applied or may have failed.`,
                  ``,
                  `To resolve this state safely, perform reconciliation via:`,
                  `  \`POST /v1/dns/deletion-requests/${tokenVerification.requestId}/reconcile\``,
                  `Or verify the live DNS zone records before attempting re-deletion.`
                ].join('\n')
              }
            ]
          };
        }

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Failed to delete DNS record: ${err instanceof Error ? err.message : String(err)}`
            }
          ]
        };
      }
    }
  );
}
