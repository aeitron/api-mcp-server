/**
 * Aeitron MCP Server — API Client Adapter
 * Bridges MCP Tools to the existing Aeitron Gateway and Commerce API
 */

import { getConfig, McpServerConfig } from './config.js';
import {
  AccountInfo,
  ProjectSummary,
  ProjectDetail,
  DnsRecord,
  UsageSummary,
  ToolContext
} from './types.js';

export class AeitronApiError extends Error {
  public status: number;
  public code?: string;

  constructor(message: string, status: number = 500, code?: string) {
    super(message);
    this.name = 'AeitronApiError';
    this.status = status;
    this.code = code;
  }
}

export class AeitronApiClient {
  private config: McpServerConfig;

  constructor(customConfig?: Partial<McpServerConfig>) {
    this.config = { ...getConfig(), ...customConfig };
  }

  private getAuthHeader(context?: ToolContext): string | undefined {
    const token = context?.token || this.config.defaultApiKey;
    if (!token) return undefined;
    if (token.startsWith('Bearer ') || token.startsWith('ApiKey ')) {
      return token;
    }
    return `Bearer ${token}`;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    context?: ToolContext,
    fallbackGenerator?: () => T
  ): Promise<T> {
    const url = `${this.config.apiBaseUrl}${endpoint}`;
    const headers = new Headers(options.headers || {});

    const authHeader = this.getAuthHeader(context);
    if (authHeader) {
      headers.set('Authorization', authHeader);
    }
    if (context?.tenantId) {
      headers.set('X-Tenant-ID', context.tenantId);
    }
    headers.set('Accept', 'application/json');
    headers.set('User-Agent', 'Aeitron-MCP-Server/0.1.0');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal
      });

      if (!response.ok) {
        let errorMsg = `Upstream API returned HTTP ${response.status} ${response.statusText}`;
        let errorCode: string | undefined;

        try {
          const errorJson = await response.json() as Record<string, unknown>;
          if (errorJson.message && typeof errorJson.message === 'string') {
            errorMsg = errorJson.message;
          } else if (errorJson.error && typeof errorJson.error === 'string') {
            errorMsg = errorJson.error;
          }
          if (errorJson.code && typeof errorJson.code === 'string') {
            errorCode = errorJson.code;
          }
        } catch {
          // Non-JSON response body
        }

        throw new AeitronApiError(errorMsg, response.status, errorCode);
      }

      return await response.json() as T;
    } catch (err: unknown) {
      if (err instanceof AeitronApiError) {
        throw err;
      }

      // If backend is offline and mock fallback is permitted
      if (this.config.mockFallback && fallbackGenerator) {
        return fallbackGenerator();
      }

      const isAbort = (err as Error)?.name === 'AbortError';
      const msg = isAbort
        ? `Request timed out after ${this.config.requestTimeoutMs}ms connecting to ${url}`
        : `Network error connecting to Aeitron API at ${url}: ${(err as Error)?.message || String(err)}`;

      throw new AeitronApiError(msg, 503, 'SERVICE_UNAVAILABLE');
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Retrieves account and quota information for the authenticated identity
   */
  public async getAccount(context?: ToolContext): Promise<AccountInfo> {
    return this.request<AccountInfo>(
      '/v1/account',
      { method: 'GET' },
      context,
      () => ({
        id: 'acc_aeitron_dev_9942',
        email: 'developer@aeitron.internal',
        name: 'Aeitron Core Developer',
        organizationId: 'org_aeitron_cloud_01',
        organizationName: 'Aeitron Cloud Workspace',
        tier: 'developer',
        status: 'active',
        limits: {
          maxProjects: 25,
          maxDomains: 100,
          monthlyBandwidthBytes: 500 * 1024 * 1024 * 1024, // 500 GB
          monthlyComputeSeconds: 3600 * 500 // 500 hours
        },
        createdAt: '2026-01-15T08:00:00Z'
      })
    );
  }

  /**
   * Lists projects under the tenant's workspace
   */
  public async listProjects(
    params: { limit?: number; offset?: number } = {},
    context?: ToolContext
  ): Promise<{ projects: ProjectSummary[]; total: number }> {
    const limit = params.limit ?? 20;
    const offset = params.offset ?? 0;
    const qs = `?limit=${limit}&offset=${offset}`;

    return this.request<{ projects: ProjectSummary[]; total: number }>(
      `/v1/projects${qs}`,
      { method: 'GET' },
      context,
      () => {
        const mockProjects: ProjectSummary[] = [
          {
            id: 'proj_gateway_edge_01',
            name: 'Production Edge Gateway',
            slug: 'prod-edge-gw',
            status: 'active',
            primaryDomain: 'api.aeitron.com',
            region: 'global-anycast',
            framework: 'rust-tokio',
            deploymentCount: 42,
            updatedAt: '2026-10-28T16:45:00Z'
          },
          {
            id: 'proj_customer_portal_02',
            name: 'Aeitron Dashboard & BFF',
            slug: 'customer-portal',
            status: 'active',
            primaryDomain: 'console.aeitron.com',
            region: 'fra1',
            framework: 'node-hono',
            deploymentCount: 19,
            updatedAt: '2026-10-28T14:20:00Z'
          },
          {
            id: 'proj_marketing_site_03',
            name: 'Public Marketing Site',
            slug: 'marketing-portal',
            status: 'active',
            primaryDomain: 'aeitron.com',
            region: 'sin1',
            framework: 'static',
            deploymentCount: 8,
            updatedAt: '2026-10-27T09:12:00Z'
          }
        ];

        return {
          projects: mockProjects.slice(offset, offset + limit),
          total: mockProjects.length
        };
      }
    );
  }

  /**
   * Retrieves single project details
   */
  public async getProject(projectId: string, context?: ToolContext): Promise<ProjectDetail> {
    return this.request<ProjectDetail>(
      `/v1/projects/${encodeURIComponent(projectId)}`,
      { method: 'GET' },
      context,
      () => ({
        id: projectId,
        name: projectId === 'prod-edge-gw' ? 'Production Edge Gateway' : `Project ${projectId}`,
        slug: projectId,
        description: 'Global anycast edge ingress node with distributed caching and TLS offload',
        status: 'active',
        primaryDomain: 'api.aeitron.com',
        region: 'global-anycast',
        framework: 'rust-tokio',
        deploymentCount: 42,
        domains: [
          {
            hostname: 'api.aeitron.com',
            status: 'verified',
            sslStatus: 'active'
          },
          {
            hostname: 'edge.aeitron.com',
            status: 'verified',
            sslStatus: 'active'
          }
        ],
        environmentVariables: [
          'DATABASE_POOL_SIZE',
          'REDIS_CLUSTER_URL',
          'LOG_LEVEL',
          'CACHE_MAX_AGE_SECONDS'
        ],
        metrics: {
          requestsLast24h: 1845920,
          bandwidthLast24hBytes: 42949672960, // ~40 GB
          p95LatencyMs: 14.8,
          uptimePercentage: 99.995
        },
        createdAt: '2026-02-01T12:00:00Z',
        updatedAt: '2026-10-28T16:45:00Z'
      })
    );
  }

  /**
   * Retrieves DNS records for a domain zone
   */
  public async getDnsRecords(domain: string, context?: ToolContext): Promise<{ records: DnsRecord[] }> {
    return this.request<{ records: DnsRecord[] }>(
      `/v1/domains/${encodeURIComponent(domain)}/records`,
      { method: 'GET' },
      context,
      () => ({
        records: [
          {
            id: 'rec_dns_a_001',
            domain,
            type: 'A',
            name: '@',
            value: '198.51.100.10',
            ttl: 300,
            proxied: true,
            status: 'active',
            updatedAt: '2026-10-25T11:00:00Z'
          },
          {
            id: 'rec_dns_aaaa_002',
            domain,
            type: 'AAAA',
            name: '@',
            value: '2001:db8::10',
            ttl: 300,
            proxied: true,
            status: 'active',
            updatedAt: '2026-10-25T11:00:00Z'
          },
          {
            id: 'rec_dns_cname_003',
            domain,
            type: 'CNAME',
            name: 'api',
            value: 'edge.aeitron.com.',
            ttl: 300,
            proxied: true,
            status: 'active',
            updatedAt: '2026-10-26T08:30:00Z'
          },
          {
            id: 'rec_dns_txt_004',
            domain,
            type: 'TXT',
            name: '_aeitron-challenge',
            value: 'aeitron-verify-94a2b901ccf',
            ttl: 60,
            proxied: false,
            status: 'active',
            updatedAt: '2026-10-25T10:45:00Z'
          }
        ]
      })
    );
  }

  /**
   * Retrieves usage summary
   */
  public async getUsage(period: 'current' | 'previous' = 'current', context?: ToolContext): Promise<UsageSummary> {
    return this.request<UsageSummary>(
      `/v1/usage?period=${period}`,
      { method: 'GET' },
      context,
      () => ({
        period,
        startDate: period === 'current' ? '2026-10-01T00:00:00Z' : '2026-09-01T00:00:00Z',
        endDate: period === 'current' ? '2026-10-28T23:59:59Z' : '2026-09-30T23:59:59Z',
        metrics: {
          edgeRequests: period === 'current' ? 14285100 : 12100400,
          bandwidthBytes: period === 'current' ? 148590000000 : 120400000000,
          computeHours: period === 'current' ? 342.5 : 280.0,
          activeDomains: 6,
          cacheHitRatioPercent: 88.4
        },
        costs: {
          currency: 'USD',
          currentEstimatedTotal: period === 'current' ? 49.00 : 45.20,
          tierBaseFee: 29.00,
          meteredOverage: period === 'current' ? 20.00 : 16.20
        }
      })
    );
  }

  /**
   * Provisions a new project container/workspace
   */
  public async createProject(
    params: { name: string; region: string; framework?: string },
    context?: ToolContext
  ): Promise<ProjectSummary> {
    const slug = params.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    return this.request<ProjectSummary>(
      '/v1/projects',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
      },
      context,
      () => ({
        id: `proj_${Date.now().toString(36)}`,
        name: params.name,
        slug,
        status: 'active',
        region: params.region,
        framework: params.framework || 'custom',
        deploymentCount: 1,
        updatedAt: new Date().toISOString()
      })
    );
  }

  /**
   * Adds a new DNS record to an authorized zone
   */
  public async createDnsRecord(
    params: { domain: string; type: 'A' | 'AAAA' | 'CNAME' | 'TXT' | 'MX'; name: string; value: string; ttl?: number; proxied?: boolean },
    context?: ToolContext
  ): Promise<DnsRecord> {
    return this.request<DnsRecord>(
      `/v1/domains/${encodeURIComponent(params.domain)}/records`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
      },
      context,
      () => ({
        id: `rec_${Date.now().toString(36)}`,
        domain: params.domain,
        type: params.type,
        name: params.name,
        value: params.value,
        ttl: params.ttl || 300,
        proxied: params.proxied ?? true,
        status: 'active',
        updatedAt: new Date().toISOString()
      })
    );
  }

  /**
   * Deletes a DNS record from the domain zone
   */
  public async deleteDnsRecord(
    params: { domain: string; recordId: string; idempotencyKey?: string },
    context?: ToolContext
  ): Promise<{ success: boolean; message: string; recordId: string }> {
    const headers: Record<string, string> = {};
    if (params.idempotencyKey) {
      headers['Idempotency-Key'] = params.idempotencyKey;
    }
    return this.request<{ success: boolean; message: string; recordId: string }>(
      `/v1/domains/${encodeURIComponent(params.domain)}/records/${encodeURIComponent(params.recordId)}`,
      { method: 'DELETE', headers },
      context,
      () => ({
        success: true,
        message: `DNS record '${params.recordId}' was successfully deleted from zone '${params.domain}'.`,
        recordId: params.recordId
      })
    );
  }
}

