/**
 * Aeitron MCP Tool — get_dns_records
 * Retrieves active DNS zone records for authorized domains
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AeitronApiClient } from '../client.js';
import { AuditLogger } from '../audit.js';

export function registerDnsTools(
  server: McpServer,
  client: AeitronApiClient,
  audit: AuditLogger
): void {
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
      const startTime = Date.now();
      try {
        const { records } = await client.getDnsRecords(args.domain);
        const duration = Date.now() - startTime;

        audit.logToolExecution('get_dns_records', args, duration, true);

        if (records.length === 0) {
          return {
            content: [
              {
                type: 'text',
                text: `No DNS records found for domain '${args.domain}'.`
              }
            ]
          };
        }

        const tableHeader = '| Type | Name | Target / Value | TTL | Proxied | Status |\n|---|---|---|---|---|---|';
        const tableRows = records.map(
          r => `| \`${r.type}\` | \`${r.name}\` | \`${r.value}\` | ${r.ttl}s | ${r.proxied ? '✓ Yes' : 'No'} | \`${r.status}\` |`
        );

        const summaryText = [
          `### DNS Records for \`${args.domain}\` (${records.length} records)`,
          tableHeader,
          ...tableRows
        ].join('\n');

        return {
          content: [
            {
              type: 'text',
              text: summaryText
            },
            {
              type: 'text',
              text: JSON.stringify({ domain: args.domain, records }, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const duration = Date.now() - startTime;
        audit.logToolExecution('get_dns_records', args, duration, false, undefined, err);

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

  // 2. create_dns_record (Phase 2 Write Tool)
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
      const startTime = Date.now();
      try {
        const record = await client.createDnsRecord(args);
        const duration = Date.now() - startTime;

        audit.logToolExecution('create_dns_record', args, duration, true);

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
        audit.logToolExecution('create_dns_record', args, duration, false, undefined, err);

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

  // 3. delete_dns_record (Phase 2 High-Risk Write Tool with Confirmation Guard)
  server.tool(
    'delete_dns_record',
    'Permanently delete a DNS record from the domain zone. Requires explicit confirmation.',
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
        .describe('Safety Confirmation: Must be explicitly true to confirm permanent deletion.')
    },
    async (args) => {
      const startTime = Date.now();

      // Guarded Safety Check: Fail closed if confirm is not explicitly true
      if (args.confirm !== true) {
        audit.logToolExecution('delete_dns_record', args, 0, false, undefined, 'Confirmation rejected');
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `⚠️ SAFETY GUARD: Deleting a DNS record is a destructive action that can disrupt live production traffic. To proceed, please ask the user for confirmation and invoke this tool with confirm: true.`
            }
          ]
        };
      }

      try {
        const result = await client.deleteDnsRecord(args);
        const duration = Date.now() - startTime;

        audit.logToolExecution('delete_dns_record', args, duration, true);

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
        audit.logToolExecution('delete_dns_record', args, duration, false, undefined, err);

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

