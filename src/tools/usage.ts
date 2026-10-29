/**
 * Aeitron MCP Tool — get_usage
 * Retrieves usage metrics, bandwidth, compute hours, and estimated billing costs.
 * Enforces scope usage:read.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AeitronApiClient } from '../client.js';
import { AuditLogger } from '../audit.js';
import { AuthClaims, checkToolAuthorization } from '../auth.js';

export function registerUsageTools(
  server: McpServer,
  client: AeitronApiClient,
  audit: AuditLogger,
  authClaims?: AuthClaims
): void {
  server.tool(
    'get_usage',
    'Retrieve bandwidth, edge request counts, microVM compute hours, and estimated billing costs for the current or previous billing cycle.',
    {
      period: z
        .enum(['current', 'previous'])
        .default('current')
        .describe('Billing cycle to query: "current" (active month to date) or "previous" (last completed month)')
    },
    async (args) => {
      const authCheck = checkToolAuthorization('get_usage', authClaims);
      if (!authCheck.authorized) {
        audit.logToolExecution('get_usage', args, 0, false, {
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
        const usage = await client.getUsage(args.period);
        const duration = Date.now() - startTime;

        audit.logToolExecution('get_usage', args, duration, true, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        });

        const bandwidthGb = (usage.metrics.bandwidthBytes / (1024 * 1024 * 1024)).toFixed(2);
        const periodTitle = args.period === 'current' ? 'Current Month-to-Date' : 'Previous Billing Period';

        const summaryText = [
          `### Aeitron Usage & Resource Consumption (${periodTitle})`,
          `- **Billing Cycle:** ${new Date(usage.startDate).toLocaleDateString()} — ${new Date(usage.endDate).toLocaleDateString()}`,
          ``,
          `#### Infrastructure Metrics`,
          `- **Edge Requests:** ${usage.metrics.edgeRequests.toLocaleString()}`,
          `- **Bandwidth Egress:** ${bandwidthGb} GB`,
          `- **Edge Cache Hit Ratio:** ${usage.metrics.cacheHitRatioPercent}%`,
          `- **Compute Runtime:** ${usage.metrics.computeHours} Hours`,
          `- **Active Custom Domains:** ${usage.metrics.activeDomains}`,
          ``,
          `#### Estimated Financials`,
          `- **Currency:** ${usage.costs.currency}`,
          `- **Base Plan Fee:** $${usage.costs.tierBaseFee.toFixed(2)}`,
          `- **Metered Overage:** $${usage.costs.meteredOverage.toFixed(2)}`,
          `- **Estimated Total:** **$${usage.costs.currentEstimatedTotal.toFixed(2)}**`
        ].join('\n');

        return {
          content: [
            {
              type: 'text',
              text: summaryText
            },
            {
              type: 'text',
              text: JSON.stringify(usage, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const duration = Date.now() - startTime;
        audit.logToolExecution('get_usage', args, duration, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, err);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Failed to get usage for period '${args.period}': ${err instanceof Error ? err.message : String(err)}`
            }
          ]
        };
      }
    }
  );
}
