/**
 * Aeitron MCP Server — Domain & Protocol Types
 */

export interface AccountInfo {
  id: string;
  email: string;
  name: string;
  organizationId: string;
  organizationName: string;
  tier: 'free' | 'developer' | 'enterprise' | 'sandbox';
  status: 'active' | 'suspended' | 'pending';
  limits: {
    maxProjects: number;
    maxDomains: number;
    monthlyBandwidthBytes: number;
    monthlyComputeSeconds: number;
  };
  createdAt: string;
}

export interface ProjectSummary {
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'deploying' | 'paused' | 'error';
  primaryDomain?: string;
  region: string;
  framework?: string;
  deploymentCount: number;
  updatedAt: string;
}

export interface ProjectDetail extends ProjectSummary {
  description?: string;
  domains: Array<{
    hostname: string;
    status: 'verified' | 'pending_dns' | 'failed';
    sslStatus: 'active' | 'issuing' | 'expired';
  }>;
  environmentVariables: string[]; // Key names only — values are never exposed to LLM context
  metrics: {
    requestsLast24h: number;
    bandwidthLast24hBytes: number;
    p95LatencyMs: number;
    uptimePercentage: number;
  };
  createdAt: string;
}

export interface DnsRecord {
  id: string;
  domain: string;
  type: 'A' | 'AAAA' | 'CNAME' | 'TXT' | 'MX' | 'NS';
  name: string;
  value: string;
  ttl: number;
  proxied: boolean;
  status: 'active' | 'propagating';
  updatedAt: string;
}

export interface UsageSummary {
  period: 'current' | 'previous';
  startDate: string;
  endDate: string;
  metrics: {
    edgeRequests: number;
    bandwidthBytes: number;
    computeHours: number;
    activeDomains: number;
    cacheHitRatioPercent: number;
  };
  costs: {
    currency: string;
    currentEstimatedTotal: number;
    tierBaseFee: number;
    meteredOverage: number;
  };
}

export interface ToolContext {
  token?: string;
  tenantId?: string;
  actorId?: string;
}

export interface AuditRecord {
  timestamp: string;
  tool: string;
  tenantId: string;
  actorId: string;
  durationMs: number;
  success: boolean;
  input: Record<string, unknown>;
  error?: string;
}

