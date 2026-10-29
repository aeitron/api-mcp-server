/**
 * Aeitron MCP Tool — DNS Zone Management (get_dns_records, create_dns_record, delete_dns_record)
 * Enforces strict tool-level scope authorization, fail-closed safety confirmation,
 * dry-run support, and cryptographic human operator challenge verification.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AeitronApiClient } from '../client.js';
import { AuditLogger } from '../audit.js';
import {
  AuthClaims,
  checkToolAuthorization,
  issueDnsDeletionChallenge,
  verifyDnsDeletionChallenge
} from '../auth.js';

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

      const tenantId = authClaims?.tenantId || 'anonymous';

      // 2. Handle Dry Run Preview
      if (args.dryRun === true) {
        const challenge = issueDnsDeletionChallenge(tenantId, args.domain, args.recordId);
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
                `- **Operator Approval Token:** \`${challenge.token}\``,
                `- **Expires:** In 5 minutes (${new Date(challenge.expiresAt).toISOString()})`,
                `- **Action Required:** To execute, human operator must approve and re-invoke delete_dns_record with \`approvalToken: "${challenge.token}"\`, \`confirm: true\`, and \`dryRun: false\`.`
              ].join('\n')
            }
          ]
        };
      }

      // 3. Challenge Guard: Reject if no approval token is provided (prevents LLM self-authorization)
      if (!args.approvalToken) {
        const challenge = issueDnsDeletionChallenge(tenantId, args.domain, args.recordId);
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
                `To prevent unintended LLM self-authorization, an explicit human approval challenge is required.`,
                ``,
                `Please ask the human user to confirm the deletion. Once confirmed, re-invoke this tool with:`,
                `- \`approvalToken\`: \`${challenge.token}\``,
                `- \`confirm\`: \`true\``,
                `- \`dryRun\`: \`false\``,
                `*(Token expires in 5 minutes)*`
              ].join('\n')
            }
          ]
        };
      }

      // 4. Verify Cryptographic Challenge Approval Token
      const tokenVerification = verifyDnsDeletionChallenge(args.approvalToken, tenantId, args.domain, args.recordId);
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

      // 5. Explicit Confirmation Boolean Check
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
              text: `⚠️ SAFETY GUARD: Valid approval token provided, but "confirm" argument must also be explicitly true to execute deletion.`
            }
          ]
        };
      }

      // 6. Perform Permanent Deletion
      const startTime = Date.now();
      try {
        const result = await client.deleteDnsRecord(args);
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
        const duration = Date.now() - startTime;
        audit.logToolExecution('delete_dns_record', args, duration, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, err);

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
