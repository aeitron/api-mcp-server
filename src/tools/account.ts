/**
 * Aeitron MCP Tool — get_account
 * Retrieves authenticated user account, tier, and resource limits
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AeitronApiClient } from '../client.js';
import { AuditLogger } from '../audit.js';

export function registerAccountTools(
  server: McpServer,
  client: AeitronApiClient,
  audit: AuditLogger
): void {
  server.tool(
    'get_account',
    'Retrieve the authenticated Aeitron account information, active organization, current subscription tier, and global resource quotas.',
    {},
    async (_args, extra) => {
      const startTime = Date.now();
      try {
        const account = await client.getAccount();
        const duration = Date.now() - startTime;

        audit.logToolExecution('get_account', {}, duration, true, {
          tenantId: account.organizationId,
          actorId: account.id
        });

        const bandwidthGb = (account.limits.monthlyBandwidthBytes / (1024 * 1024 * 1024)).toFixed(0);
        const computeHours = (account.limits.monthlyComputeSeconds / 3600).toFixed(0);

        const summaryText = [
          `### Aeitron Account Overview`,
          `- **User:** ${account.name} (\`${account.email}\`)`,
          `- **Organization:** ${account.organizationName} (\`${account.organizationId}\`)`,
          `- **Subscription Tier:** \`${account.tier.toUpperCase()}\` (Status: \`${account.status}\`)`,
          `- **Account Created:** ${new Date(account.createdAt).toLocaleDateString()}`,
          ``,
          `#### Quota & Resource Limits`,
          `- **Max Projects:** ${account.limits.maxProjects}`,
          `- **Max Domains:** ${account.limits.maxDomains}`,
          `- **Monthly Bandwidth:** ${bandwidthGb} GB`,
          `- **Monthly Compute Hours:** ${computeHours} Hours`
        ].join('\n');

        return {
          content: [
            {
              type: 'text',
              text: summaryText
            },
            {
              type: 'text',
              text: JSON.stringify(account, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const duration = Date.now() - startTime;
        audit.logToolExecution('get_account', {}, duration, false, undefined, err);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Failed to fetch account info: ${err instanceof Error ? err.message : String(err)}`
            }
          ]
        };
      }
    }
  );
}

