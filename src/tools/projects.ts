/**
 * Aeitron MCP Tools — list_projects, get_project, create_project
 * Enforces per-tool scope validation and secure tenant context.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AeitronApiClient } from '../client.js';
import { AuditLogger } from '../audit.js';
import { AuthClaims, checkToolAuthorization } from '../auth.js';

export function registerProjectTools(
  server: McpServer,
  client: AeitronApiClient,
  audit: AuditLogger,
  authClaims?: AuthClaims
): void {
  // 1. list_projects (Scope: projects:read)
  server.tool(
    'list_projects',
    'List all projects accessible to the current tenant, including status, regions, primary domains, and total deployment counts.',
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(20)
        .describe('Maximum number of projects to return (1-100, default 20)'),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe('Zero-based offset index for pagination (default 0)')
    },
    async (args) => {
      const authCheck = checkToolAuthorization('list_projects', authClaims);
      if (!authCheck.authorized) {
        audit.logToolExecution('list_projects', args, 0, false, {
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
        const { projects, total } = await client.listProjects(args);
        const duration = Date.now() - startTime;

        audit.logToolExecution('list_projects', args, duration, true, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        });

        if (projects.length === 0) {
          return {
            content: [
              {
                type: 'text',
                text: 'No projects found in this organization.'
              }
            ]
          };
        }

        const formattedRows = projects.map(
          (p) =>
            `- **${p.name}** (\`${p.slug}\`)\n  - ID: \`${p.id}\`\n  - Domain: \`${p.primaryDomain || 'No domain attached'}\`\n  - Status: \`${p.status}\` | Region: \`${p.region}\` | Deployments: ${p.deploymentCount}`
        );

        const summaryText = [
          `### Projects Inventory (${projects.length} of ${total} shown)`,
          ...formattedRows
        ].join('\n');

        return {
          content: [
            {
              type: 'text',
              text: summaryText
            },
            {
              type: 'text',
              text: JSON.stringify({ total, count: projects.length, projects }, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const duration = Date.now() - startTime;
        audit.logToolExecution('list_projects', args, duration, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, err);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Failed to list projects: ${err instanceof Error ? err.message : String(err)}`
            }
          ]
        };
      }
    }
  );

  // 2. get_project (Scope: projects:read)
  server.tool(
    'get_project',
    'Retrieve detailed status, environments, domain mappings, and performance metrics for a specific project.',
    {
      projectId: z
        .string()
        .min(1)
        .describe('The unique project ID or slug (e.g. "prod-edge-gw" or "proj_gateway_edge_01")')
    },
    async (args) => {
      const authCheck = checkToolAuthorization('get_project', authClaims);
      if (!authCheck.authorized) {
        audit.logToolExecution('get_project', args, 0, false, {
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
        const project = await client.getProject(args.projectId);
        const duration = Date.now() - startTime;

        audit.logToolExecution('get_project', args, duration, true, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        });

        const bandwidthGb = (project.metrics.bandwidthLast24hBytes / (1024 * 1024 * 1024)).toFixed(2);
        const domainsList = project.domains.map(d => `  - \`${d.hostname}\` (DNS: \`${d.status}\`, SSL: \`${d.sslStatus}\`)`).join('\n');
        const envKeys = project.environmentVariables.length > 0
          ? project.environmentVariables.map(k => `\`${k}\``).join(', ')
          : 'None defined';

        const summaryText = [
          `### Project: ${project.name} (\`${project.slug}\`)`,
          `- **ID:** \`${project.id}\``,
          `- **Status:** \`${project.status}\``,
          `- **Primary Domain:** \`${project.primaryDomain || 'None'}\``,
          `- **Region:** \`${project.region}\``,
          `- **Framework:** \`${project.framework || 'Custom'}\``,
          `- **Total Deployments:** ${project.deploymentCount}`,
          ``,
          `#### Attached Domains`,
          domainsList || '  - No custom domains attached',
          ``,
          `#### 24h Telemetry & Performance`,
          `- **Requests (24h):** ${project.metrics.requestsLast24h.toLocaleString()}`,
          `- **Bandwidth (24h):** ${bandwidthGb} GB`,
          `- **P95 Edge Latency:** ${project.metrics.p95LatencyMs} ms`,
          `- **Uptime:** ${project.metrics.uptimePercentage}%`,
          ``,
          `#### Configured Environment Variables (Keys Only)`,
          envKeys
        ].join('\n');

        return {
          content: [
            {
              type: 'text',
              text: summaryText
            },
            {
              type: 'text',
              text: JSON.stringify(project, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const duration = Date.now() - startTime;
        audit.logToolExecution('get_project', args, duration, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, err);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Failed to get project '${args.projectId}': ${err instanceof Error ? err.message : String(err)}`
            }
          ]
        };
      }
    }
  );

  // 3. create_project (Scope: projects:write)
  server.tool(
    'create_project',
    'Provision a new infrastructure project workspace on the Aeitron edge network.',
    {
      name: z
        .string()
        .min(2)
        .max(64)
        .describe('Human-readable project name (e.g. "Payment Gateway Service")'),
      region: z
        .enum(['global-anycast', 'sin1', 'fra1', 'iad1', 'dac1'])
        .default('global-anycast')
        .describe('Deployment region / PoP placement target'),
      framework: z
        .string()
        .optional()
        .describe('Optional technology or framework preset (e.g. "rust-tokio", "node-hono", "static", "python")')
    },
    async (args) => {
      const authCheck = checkToolAuthorization('create_project', authClaims);
      if (!authCheck.authorized) {
        audit.logToolExecution('create_project', args, 0, false, {
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
        const project = await client.createProject(args);
        const duration = Date.now() - startTime;

        audit.logToolExecution('create_project', args, duration, true, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        });

        const summaryText = [
          `### Project Created Successfully! 🎉`,
          `- **Name:** ${project.name}`,
          `- **ID:** \`${project.id}\``,
          `- **Slug:** \`${project.slug}\``,
          `- **Region:** \`${project.region}\``,
          `- **Framework:** \`${project.framework}\``,
          `- **Status:** \`${project.status}\``
        ].join('\n');

        return {
          content: [
            {
              type: 'text',
              text: summaryText
            },
            {
              type: 'text',
              text: JSON.stringify(project, null, 2)
            }
          ]
        };
      } catch (err: unknown) {
        const duration = Date.now() - startTime;
        audit.logToolExecution('create_project', args, duration, false, {
          tenantId: authClaims?.tenantId,
          actorId: authClaims?.actorId
        }, err);

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Failed to create project: ${err instanceof Error ? err.message : String(err)}`
            }
          ]
        };
      }
    }
  );
}
