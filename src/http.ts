/**
 * Aeitron MCP Server — Hardened Remote Streamable HTTP & SSE Server
 * Enforces per-session cryptographic authentication, tool-level RBAC scopes,
 * CORS origin allowlists with preflight handling, authenticated OAuth client credentials,
 * and standard Streamable HTTP + backward-compatible SSE transports.
 */

import http, { IncomingMessage, ServerResponse } from 'node:http';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getRequestListener } from '@hono/node-server';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createAeitronMcpServer } from './server.js';
import {
  AuthClaims,
  extractTokenFromRequest,
  verifyAuthToken,
  getOAuthDiscoveryMetadata,
  getJwksMetadata,
  createSignedTestJwt,
  issueOAuthAccessToken,
  verifyOAuthClient,
  registerOAuthClientForTesting,
  authorizeDnsDeletionRequest,
  getDnsDeletionRequest,
  getPendingDnsDeletionRequest,
  listPendingDnsDeletionRequests,
  toRedactedDnsRequestDto,
  reconcileDnsDeletionStatus,
  hasRecentHumanMfa,
  isStorageReady,
  isRsaReady
} from './auth.js';
import { getConfig, McpServerConfig } from './config.js';
import { ToolContext } from './types.js';
import { AeitronApiClient } from './client.js';

interface ActiveSession {
  sessionId: string;
  transport: SSEServerTransport;
  serverInstance: ReturnType<typeof createAeitronMcpServer>;
  context: ToolContext;
  createdAt: Date;
  lastActiveAt: number;
}

export interface McpHttpServerInstance {
  httpServer: http.Server;
  app: Hono;
  activeSessions: Map<string, ActiveSession>;
  close: () => Promise<void>;
  port: number;
}

export function createMcpHttpServer(
  customConfig?: Partial<McpServerConfig>
): McpHttpServerInstance {
  const config = { ...getConfig(), ...customConfig };
  const app = new Hono();
  const activeSessions = new Map<string, ActiveSession>();
  const streamableSessions = new Map<string, {
    transport: StreamableHTTPServerTransport;
    serverInstance: ReturnType<typeof createAeitronMcpServer>;
    claims: AuthClaims;
    createdAt: number;
    lastActiveAt: number;
  }>();

  // Session Capacity Guard with pending reservation counter to prevent async race conditions
  let pendingSessionCreations = 0;
  function reserveSessionSlot(): boolean {
    const activeCount = streamableSessions.size + activeSessions.size + pendingSessionCreations;
    if (activeCount >= config.maxActiveSessions) {
      return false;
    }
    pendingSessionCreations += 1;
    return true;
  }
  function releaseSessionSlot(): void {
    pendingSessionCreations = Math.max(0, pendingSessionCreations - 1);
  }

  // In-memory token bucket rate limiter for sensitive endpoints with bounded capacity and idle eviction
  const MAX_RATE_LIMIT_BUCKETS = 10000;
  const rateLimitBuckets = new Map<string, { tokens: number; lastRefill: number }>();

  function sweepRateLimitBuckets(now = Date.now()): void {
    for (const [key, bucket] of rateLimitBuckets.entries()) {
      if (now - bucket.lastRefill > 3600000) {
        rateLimitBuckets.delete(key);
      }
    }
    if (rateLimitBuckets.size > MAX_RATE_LIMIT_BUCKETS) {
      const entries = Array.from(rateLimitBuckets.entries())
        .sort((a, b) => a[1].lastRefill - b[1].lastRefill);
      const toRemove = entries.slice(0, entries.length - MAX_RATE_LIMIT_BUCKETS);
      for (const [k] of toRemove) {
        rateLimitBuckets.delete(k);
      }
    }
  }

  function checkRateLimit(key: string, capacity = 60, refillPerSec = 1): boolean {
    const now = Date.now();
    let bucket = rateLimitBuckets.get(key);
    if (!bucket) {
      if (rateLimitBuckets.size >= MAX_RATE_LIMIT_BUCKETS) {
        sweepRateLimitBuckets(now);
      }
      bucket = { tokens: capacity - 1, lastRefill: now };
      rateLimitBuckets.set(key, bucket);
      return true;
    }
    const elapsed = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsed * refillPerSec);
    bucket.lastRefill = now;
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return true;
    }
    return false;
  }

  const startTime = Date.now();

  const isHardened = config.environment === 'production' || config.environment === 'staging';
  // Test fixture OAuth client is strictly restricted to non-hardened environments (dev and test)
  if (!isHardened) {
    registerOAuthClientForTesting({
      clientId: 'aeitron_test_client_id',
      clientSecretHash: 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', // hash of 'secret_test_key_889'
      tenantId: 'tenant_test_workspace',
      actorId: 'usr_test_client',
      scopes: ['account:read', 'projects:read', 'dns:read', 'usage:read']
    });
  }

  // 1. Strict CORS Middleware for Hono routes
  app.use('*', cors({
    origin: (origin) => {
      if (!origin) return config.corsAllowedOrigins[0] || '*';
      if (config.corsAllowedOrigins.includes('*') || config.corsAllowedOrigins.includes(origin)) {
        return origin;
      }
      return null;
    },
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: [
      'Content-Type',
      'Authorization',
      'X-Request-ID',
      'X-Tenant-ID',
      'Mcp-Session-Id',
      'Last-Event-ID',
      'MCP-Protocol-Version',
      'Mcp-Protocol-Version',
      'Mcp-Method',
      'Mcp-Name',
      'X-Aeitron-Approval-Token'
    ],
    exposeHeaders: ['X-Request-ID', 'X-Session-ID', 'Mcp-Session-Id', 'MCP-Protocol-Version', 'Mcp-Protocol-Version'],
    maxAge: 86400
  }));

  // 2. Health & Readiness Probes
  app.get('/health', (c) => {
    return c.json({
      status: 'ok',
      service: 'aeitron-mcp-server',
      version: '1.0.0',
      environment: config.environment,
      uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
      activeSessions: activeSessions.size + streamableSessions.size,
      mockFallbackEnabled: config.mockFallback
    });
  });

  app.get('/ready', (c) => {
    const rsaReady = isRsaReady();
    const storageReady = isStorageReady();
    const isReady = rsaReady && storageReady;

    if (!isReady) {
      return c.json({
        ready: false,
        service: 'aeitron-mcp-server',
        checks: {
          rsa: rsaReady ? 'ok' : 'unready',
          storage: storageReady ? 'ok' : 'unready'
        }
      }, 503);
    }

    return c.json({
      ready: true,
      service: 'aeitron-mcp-server',
      checks: {
        rsa: 'ok',
        storage: 'ok'
      },
      supportedTransports: ['stdio', 'streamable-http', 'sse'],
      toolsAvailable: [
        'get_account',
        'list_projects',
        'get_project',
        'get_dns_records',
        'get_usage',
        'create_project',
        'create_dns_record',
        'delete_dns_record'
      ]
    });
  });

  // 3. RFC 8414 OAuth 2.0 Authorization Server Discovery
  const oauthHandler = (c: { json: (data: unknown) => Response }) => {
    return c.json(getOAuthDiscoveryMetadata(config.apiBaseUrl));
  };
  app.get('/.well-known/oauth-authorization-server', oauthHandler);
  app.get('/mcp/.well-known/oauth-authorization-server', oauthHandler);

  // 4. RFC 7517 JSON Web Key Set (JWKS) Discovery
  const jwksHandler = (c: { json: (data: unknown) => Response }) => {
    return c.json(getJwksMetadata());
  };
  app.get('/.well-known/jwks.json', jwksHandler);
  app.get('/mcp/.well-known/jwks.json', jwksHandler);

  // 5. Authenticated OAuth 2.0 Token Exchange Endpoint
  // Enforces client authentication (Basic Auth or JSON body) — zero unauthenticated tokens!
  app.post('/v1/auth/token', async (c) => {
    const clientIp = (c.req.header('x-aeitron-socket-ip') || '127.0.0.1').trim();
    if (!checkRateLimit(`auth_token:${clientIp}`, 100, 5)) {
      return c.json({
        error: 'slow_down',
        error_description: 'Rate limit exceeded on token endpoint. Please wait before retrying.'
      }, 429);
    }

    let clientId: string | undefined;
    let clientSecret: string | undefined;

    // Check Basic Auth header: Authorization: Basic <base64(client_id:client_secret)>
    const authHeader = c.req.header('authorization');
    if (authHeader && authHeader.startsWith('Basic ')) {
      try {
        const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf-8');
        const colonIdx = decoded.indexOf(':');
        if (colonIdx !== -1) {
          clientId = decoded.slice(0, colonIdx);
          clientSecret = decoded.slice(colonIdx + 1);
        }
      } catch {
        // Fallback to body parsing
      }
    }

    const body = await c.req.json().catch(() => ({}));
    if (!clientId && body.client_id) {
      clientId = String(body.client_id);
    }
    if (!clientSecret && body.client_secret) {
      clientSecret = String(body.client_secret);
    }

    if (body.grant_type !== 'client_credentials') {
      return c.json({
        error: 'unsupported_grant_type',
        error_description: 'Only grant_type=client_credentials is supported.'
      }, 400);
    }

    // Fail-Closed: Client credentials verification is mandatory
    if (!clientId || !clientSecret) {
      return c.json({
        error: 'invalid_client',
        error_description: 'Client authentication failed: missing client_id or client_secret.'
      }, 401);
    }

    const verification = verifyOAuthClient(clientId, clientSecret);
    if (!verification.success) {
      return c.json({
        error: 'unauthorized_client',
        error_description: verification.error
      }, 401);
    }

    const client = verification.client;
    // Issue RFC 7519 / RFC 7517 compliant RS256 token matching the published JWKS public keys
    const token = issueOAuthAccessToken(client);

    return c.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: client.scopes.join(' ')
    });
  });

  // 5b. Authenticated Human Operator DNS Deletion Approval Endpoint
  // Bridges MCP DNS deletion challenge requests to authorized operator console/CLI
  const dnsApprovalHandler = async (c: any) => {
    const host = c.req.header('host') || 'localhost';
    const parsedUrl = new URL(c.req.url, `http://${host}`);
    const { token: rawToken } = extractTokenFromRequest(c.req.raw, parsedUrl);

    const auth = verifyAuthToken(rawToken, {
      isProduction: config.environment === 'production',
      allowSandbox: config.allowSandbox,
      jwtSecret: config.jwtSecret,
      requiredScopes: ['dns:delete:approve']
    });

    if (!auth.success) {
      return c.json({
        error: 'unauthorized',
        error_description: auth.error
      }, auth.status);
    }

    // P1 Guard: DNS deletion approval requires a verified human operator with recent MFA
    if (!hasRecentHumanMfa(auth.claims)) {
      return c.json({
        error: 'human_verification_required',
        error_description: 'DNS deletion approval requires an authenticated human operator with recent MFA verification (within 5 minutes).'
      }, 403);
    }

    if (!checkRateLimit(`dns_approve:${auth.claims.tenantId}`, 60, 2)) {
      return c.json({
        error: 'rate_limit_exceeded',
        error_description: 'Rate limit exceeded on DNS deletion approvals for this tenant.'
      }, 429);
    }

    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    const requestId = String(body['requestId'] || body['request_id'] || '').trim();

    if (!requestId) {
      return c.json({
        error: 'invalid_request',
        error_description: 'Missing mandatory "requestId" field in JSON body.'
      }, 400);
    }

    const result = authorizeDnsDeletionRequest(auth.claims, requestId);
    if (!result.success) {
      return c.json({
        error: result.status === 403 ? 'forbidden' : result.status === 404 ? 'not_found' : 'invalid_request',
        error_description: result.error
      }, result.status);
    }

    return c.json({
      success: true,
      requestId: result.requestId,
      approvalToken: result.token,
      expiresAt: result.expiresAt,
      domain: result.domain,
      recordId: result.recordId,
      message: 'DNS deletion request successfully authorized. Provide this approvalToken to delete_dns_record.'
    });
  };

  app.post('/v1/dns/approve-deletion', dnsApprovalHandler);
  app.post('/mcp/dns/approve-deletion', dnsApprovalHandler);

  // List pending DNS deletion requests awaiting approval (Redacted DTO, strictly omits approvalToken)
  app.get('/v1/dns/deletion-requests', (c: any) => {
    const host = c.req.header('host') || 'localhost';
    const parsedUrl = new URL(c.req.url, `http://${host}`);
    const { token: rawToken } = extractTokenFromRequest(c.req.raw, parsedUrl);

    const auth = verifyAuthToken(rawToken, {
      isProduction: config.environment === 'production',
      allowSandbox: config.allowSandbox,
      jwtSecret: config.jwtSecret
    });

    if (!auth.success) {
      return c.json({ error: 'unauthorized', error_description: auth.error }, auth.status);
    }

    // Privileged operator scope enforcement
    const hasOperatorScope = auth.claims.scopes.includes('dns:delete:approve') ||
      auth.claims.scopes.includes('dns:write:delete') ||
      auth.claims.scopes.includes('dns:write') ||
      auth.claims.scopes.includes('*');
    if (!hasOperatorScope) {
      return c.json({
        error: 'forbidden',
        error_description: 'Access denied: Viewing pending DNS deletion requests requires operator scope "dns:delete:approve", "dns:write:delete", or "dns:write".'
      }, 403);
    }

    const requests = listPendingDnsDeletionRequests(auth.claims.tenantId).map(toRedactedDnsRequestDto);
    return c.json({ requests });
  });

  // Get specific DNS deletion request details (Redacted DTO, strictly omits approvalToken)
  app.get('/v1/dns/deletion-requests/:id', (c: any) => {
    const host = c.req.header('host') || 'localhost';
    const parsedUrl = new URL(c.req.url, `http://${host}`);
    const { token: rawToken } = extractTokenFromRequest(c.req.raw, parsedUrl);

    const auth = verifyAuthToken(rawToken, {
      isProduction: config.environment === 'production',
      allowSandbox: config.allowSandbox,
      jwtSecret: config.jwtSecret
    });

    if (!auth.success) {
      return c.json({ error: 'unauthorized', error_description: auth.error }, auth.status);
    }

    // Privileged operator scope enforcement
    const hasOperatorScope = auth.claims.scopes.includes('dns:delete:approve') ||
      auth.claims.scopes.includes('dns:write:delete') ||
      auth.claims.scopes.includes('dns:write') ||
      auth.claims.scopes.includes('*');
    if (!hasOperatorScope) {
      return c.json({
        error: 'forbidden',
        error_description: 'Access denied: Viewing pending DNS deletion requests requires operator scope "dns:write:delete" or "dns:write".'
      }, 403);
    }

    const reqId = c.req.param('id');
    const request = getDnsDeletionRequest(reqId);
    const tenantId = auth.claims.tenantId;
    if (!request || !tenantId || tenantId === 'anonymous' || request.tenantId !== tenantId) {
      return c.json({ error: 'not_found', error_description: 'Deletion request not found or expired.' }, 404);
    }

    return c.json({ request: toRedactedDnsRequestDto(request) });
  });

  // Reconcile status of a DNS deletion request against live zone truth
  app.post('/v1/dns/deletion-requests/:id/reconcile', async (c: any) => {
    const host = c.req.header('host') || 'localhost';
    const parsedUrl = new URL(c.req.url, `http://${host}`);
    const { token: rawToken } = extractTokenFromRequest(c.req.raw, parsedUrl);

    const auth = verifyAuthToken(rawToken, {
      isProduction: config.environment === 'production',
      allowSandbox: config.allowSandbox,
      jwtSecret: config.jwtSecret
    });

    if (!auth.success) {
      return c.json({ error: 'unauthorized', error_description: auth.error }, auth.status);
    }

    // Explicit Dual-Scope Authorization: Reconciliation requires both approval and DNS read privileges
    const hasApproveScope =
      auth.claims.scopes.includes('dns:delete:approve') ||
      auth.claims.scopes.includes('*');
    const hasReadScope =
      auth.claims.scopes.includes('dns:read') ||
      auth.claims.scopes.includes('dns:write') ||
      auth.claims.scopes.includes('*');

    if (!hasApproveScope || !hasReadScope) {
      return c.json({
        error: 'forbidden',
        error_description: 'Access denied: Reconciliation requires both "dns:delete:approve" and "dns:read" scopes.'
      }, 403);
    }

    const reqId = c.req.param('id');
    const tenantId = auth.claims.tenantId;

    if (!checkRateLimit(`dns_reconcile:${tenantId}`, 60, 2)) {
      return c.json({
        error: 'rate_limit_exceeded',
        error_description: 'Rate limit exceeded on DNS deletion reconciliation for this tenant.'
      }, 429);
    }

    const request = getDnsDeletionRequest(reqId);
    if (!request || !tenantId || tenantId === 'anonymous' || request.tenantId !== tenantId) {
      return c.json({ error: 'not_found', error_description: 'Deletion request not found or expired.' }, 404);
    }

    const apiClient = new AeitronApiClient({
      ...config,
      defaultApiKey: auth.token
    });

    try {
      const { records } = await apiClient.getDnsRecords(request.domain);
      const recordStillExists = records.some((r) => r.id === request.recordId);
      const reconciled = reconcileDnsDeletionStatus(reqId, recordStillExists);

      return c.json({
        success: reconciled.success,
        requestId: reqId,
        status: reconciled.status,
        domain: request.domain,
        recordId: request.recordId,
        recordStillExists
      });
    } catch (err: unknown) {
      process.stderr.write(
        `[aeitron-mcp] DNS reconciliation failed for request ${reqId}: ${err instanceof Error ? err.message : String(err)}\n`
      );
      return c.json({
        error: 'reconciliation_failed',
        error_description: 'Unable to verify the deletion outcome. The request remains unresolved; retry reconciliation.'
      }, 502);
    }
  });

  // 6. Welcome & Discovery
  app.get('/', (c) => {
    return c.json({
      name: 'Aeitron Infrastructure MCP Server',
      description: 'Official Model Context Protocol server connecting AI clients with Aeitron Cloud & Edge Infrastructure',
      version: '1.0.0',
      endpoints: {
        streamableHttp: '/mcp',
        sse: '/mcp/sse',
        messages: '/mcp/messages?sessionId={id}',
        health: '/health',
        ready: '/ready',
        oauthMetadata: '/.well-known/oauth-authorization-server',
        jwks: '/.well-known/jwks.json'
      },
      documentation: 'https://docs.aeitron.com/mcp'
    });
  });

  const honoListener = getRequestListener(app.fetch);

  // 7. Main Node HTTP Dispatcher with Centralized CORS Preflight & Transport Routing
  const httpServer = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const socketIp = req.socket?.remoteAddress || '127.0.0.1';
    req.headers['x-aeitron-socket-ip'] = socketIp;
    const host = req.headers.host || 'localhost';
    const parsedUrl = new URL(req.url || '/', `http://${host}`);
    const pathname = parsedUrl.pathname;
    const origin = req.headers.origin;

    // A. Centralized CORS Handling for all Node HTTP Dispatcher routes
    let isOriginAllowed = false;
    let allowedOriginHeader: string | null = null;

    if (config.corsAllowedOrigins.includes('*')) {
      isOriginAllowed = true;
      allowedOriginHeader = origin || '*';
    } else if (origin && config.corsAllowedOrigins.includes(origin)) {
      isOriginAllowed = true;
      allowedOriginHeader = origin;
    }

    if (origin) {
      if (isOriginAllowed && allowedOriginHeader) {
        res.setHeader('Access-Control-Allow-Origin', allowedOriginHeader);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader(
          'Access-Control-Allow-Headers',
          'Content-Type, Authorization, X-Request-ID, X-Tenant-ID, Mcp-Session-Id, Last-Event-ID, MCP-Protocol-Version, Mcp-Protocol-Version, Mcp-Method, Mcp-Name, X-Aeitron-Approval-Token'
        );
        res.setHeader(
          'Access-Control-Expose-Headers',
          'X-Request-ID, X-Session-ID, Mcp-Session-Id, MCP-Protocol-Version, Mcp-Protocol-Version'
        );
        res.setHeader('Access-Control-Max-Age', '86400');
      } else if (config.environment === 'production' || config.environment === 'staging') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `CORS policy error: Origin '${origin}' is not allowed in ${config.environment}.` }));
        return;
      }
    }

    // Handle preflight OPTIONS requests across all endpoints
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Top-Level Guard: Reject authentication tokens in URL query strings in hardened environments
    // Prevents credential leakage across web server logs, proxy access logs, and HTTP referrers
    const isHardened = config.environment === 'production' || config.environment === 'staging';
    const authQueryParams = ['token', 'apiKey', 'api_key', 'access_token'];
    if (isHardened && authQueryParams.some((k) => parsedUrl.searchParams.has(k))) {
      res.writeHead(400, {
        'Content-Type': 'application/problem+json',
        'Cache-Control': 'no-store'
      });
      res.end(
        JSON.stringify({
          type: 'https://aeitron.com/errors/invalid-auth-transport',
          title: 'Invalid Authentication Transport',
          status: 400,
          detail: 'Passing authentication tokens via URL query parameters is strictly prohibited in production and staging environments. Authentication tokens must be sent using the Authorization: Bearer <token> header.'
        })
      );
      return;
    }

    // B. Modern Streamable HTTP Endpoint (/mcp)
    if (pathname === '/mcp') {
      const { token: rawToken } = extractTokenFromRequest(req, parsedUrl);
      const auth = verifyAuthToken(rawToken, {
        isProduction: config.environment === 'production',
        allowSandbox: config.allowSandbox,
        jwtSecret: config.jwtSecret
      });

      if (!auth.success) {
        res.writeHead(auth.status, {
          'Content-Type': 'application/problem+json',
          'WWW-Authenticate': 'Bearer realm="Aeitron MCP"'
        });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/unauthorized',
          title: auth.code,
          status: auth.status,
          detail: auth.error
        }));
        return;
      }

      const sessionIdHeader = (req.headers['mcp-session-id'] as string) || parsedUrl.searchParams.get('sessionId') || undefined;

      // Handle DELETE to explicitly terminate a session
      if (req.method === 'DELETE') {
        if (sessionIdHeader && streamableSessions.has(sessionIdHeader)) {
          const session = streamableSessions.get(sessionIdHeader)!;
          // Security Check: Cross-Tenant Session Binding
          if (session.claims.tenantId !== auth.claims.tenantId || session.claims.actorId !== auth.claims.actorId) {
            res.writeHead(403, { 'Content-Type': 'application/problem+json' });
            res.end(JSON.stringify({
              type: 'https://aeitron.com/errors/forbidden',
              title: 'Forbidden',
              status: 403,
              detail: 'Cross-tenant session access prohibited. Authenticated caller identity does not match session owner.'
            }));
            return;
          }
          await session.transport.close();
          await session.serverInstance.server.close();
          streamableSessions.delete(sessionIdHeader);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'session_terminated', sessionId: sessionIdHeader }));
          return;
        }
        res.writeHead(404, { 'Content-Type': 'application/problem+json' });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/session-not-found',
          title: 'Session Not Found',
          status: 404,
          detail: `Streamable HTTP session '${sessionIdHeader}' not found.`
        }));
        return;
      }

      // Handle GET for SSE streaming connection on an existing session
      if (req.method === 'GET') {
        if (sessionIdHeader && streamableSessions.has(sessionIdHeader)) {
          const session = streamableSessions.get(sessionIdHeader)!;
          // Security Check: Cross-Tenant Session Binding
          if (session.claims.tenantId !== auth.claims.tenantId || session.claims.actorId !== auth.claims.actorId) {
            res.writeHead(403, { 'Content-Type': 'application/problem+json' });
            res.end(JSON.stringify({
              type: 'https://aeitron.com/errors/forbidden',
              title: 'Forbidden',
              status: 403,
              detail: 'Cross-tenant session access prohibited. Authenticated caller identity does not match session owner.'
            }));
            return;
          }
          session.lastActiveAt = Date.now();
          await session.transport.handleRequest(req, res);
          return;
        }
        res.writeHead(404, { 'Content-Type': 'application/problem+json' });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/session-not-found',
          title: 'Session Not Found',
          status: 404,
          detail: `Streamable HTTP session '${sessionIdHeader}' not found.`
        }));
        return;
      }

      // Handle POST for JSON-RPC operations
      if (req.method === 'POST') {
        if (sessionIdHeader) {
          const session = streamableSessions.get(sessionIdHeader);
          if (!session) {
            res.writeHead(404, { 'Content-Type': 'application/problem+json' });
            res.end(JSON.stringify({
              type: 'https://aeitron.com/errors/session-not-found',
              title: 'Session Not Found',
              status: 404,
              detail: `Streamable HTTP session '${sessionIdHeader}' was not found or has expired.`
            }));
            return;
          }
          // Security Check: Cross-Tenant Session Binding
          if (session.claims.tenantId !== auth.claims.tenantId || session.claims.actorId !== auth.claims.actorId) {
            res.writeHead(403, { 'Content-Type': 'application/problem+json' });
            res.end(JSON.stringify({
              type: 'https://aeitron.com/errors/forbidden',
              title: 'Forbidden',
              status: 403,
              detail: 'Cross-tenant session access prohibited. Authenticated caller identity does not match session owner.'
            }));
            return;
          }
          session.lastActiveAt = Date.now();
          await session.transport.handleRequest(req, res);
          return;
        }

        // Capacity Guard: Maximum active sessions limit with reservation lock
        if (!reserveSessionSlot()) {
          res.writeHead(503, {
            'Content-Type': 'application/problem+json',
            'Retry-After': '30'
          });
          res.end(JSON.stringify({
            type: 'https://aeitron.com/errors/service-unavailable',
            title: 'Service Unavailable',
            status: 503,
            detail: `Maximum active sessions capacity (${config.maxActiveSessions}) reached. Please retry later.`
          }));
          return;
        }

        let sessionId: string | undefined;
        let transport: StreamableHTTPServerTransport | undefined;
        let serverInstance: ReturnType<typeof createAeitronMcpServer> | undefined;

        try {
          // Fresh session initialization or stateless invocation
          sessionId = crypto.randomUUID();
          const apiClient = new AeitronApiClient({
            ...config,
            defaultApiKey: auth.token
          });

          serverInstance = createAeitronMcpServer({
            config,
            client: apiClient,
            authClaims: auth.claims
          });

          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => sessionId!,
            enableJsonResponse: true,
            onsessionclosed: (closedId) => {
              streamableSessions.delete(closedId);
            }
          });

          await serverInstance.server.connect(transport);
          streamableSessions.set(sessionId, {
            transport,
            serverInstance,
            claims: auth.claims,
            createdAt: Date.now(),
            lastActiveAt: Date.now()
          });

          await transport.handleRequest(req, res);
          // If the initial request resulted in an error status, clean up immediately so dead sessions do not leak
          if (res.statusCode >= 400) {
            streamableSessions.delete(sessionId);
            transport.close().catch(() => {});
            serverInstance.server.close().catch(() => {});
          }
        } catch (err) {
          if (sessionId) {
            streamableSessions.delete(sessionId);
          }
          if (transport) {
            transport.close().catch(() => {});
          }
          if (serverInstance) {
            serverInstance.server.close().catch(() => {});
          }
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/problem+json' });
            res.end(JSON.stringify({
              type: 'https://aeitron.com/errors/internal-server-error',
              title: 'Internal Server Error',
              status: 500,
              detail: 'Failed to initialize or process MCP session request.'
            }));
          }
        } finally {
          releaseSessionSlot();
        }
        return;
      }

      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Method Not Allowed. Use GET, POST, or DELETE for /mcp.' }));
      return;
    }

    // C. Legacy SSE Handshake (/mcp/sse or /sse) for backward compatibility
    if (pathname === '/mcp/sse' || pathname === '/sse') {
      if (req.method !== 'GET') {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Method Not Allowed. Use GET for SSE stream.' }));
        return;
      }

      // Authenticate SSE connection
      const { token: rawToken, wasInQuery } = extractTokenFromRequest(req, parsedUrl);
      if (wasInQuery && (config.environment === 'production' || config.environment === 'staging')) {
        res.writeHead(400, {
          'Content-Type': 'application/problem+json'
        });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/invalid-auth-transport',
          title: 'Invalid Authentication Transport',
          status: 400,
          detail: 'Passing authentication tokens via URL query parameters is strictly prohibited in production and staging environments. Use the Authorization: Bearer <token> header.'
        }));
        return;
      }

      const auth = verifyAuthToken(rawToken, {
        isProduction: config.environment === 'production',
        allowSandbox: config.allowSandbox,
        jwtSecret: config.jwtSecret
      });

      if (!auth.success) {
        res.writeHead(auth.status, {
          'Content-Type': 'application/problem+json',
          'WWW-Authenticate': 'Bearer realm="Aeitron MCP"'
        });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/unauthorized',
          title: auth.code,
          status: auth.status,
          detail: auth.error
        }));
        return;
      }

      // Capacity Guard: Maximum active sessions limit on SSE Handshake with reservation lock
      if (!reserveSessionSlot()) {
        res.writeHead(503, {
          'Content-Type': 'application/problem+json',
          'Retry-After': '30'
        });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/service-unavailable',
          title: 'Service Unavailable',
          status: 503,
          detail: `Maximum active sessions capacity (${config.maxActiveSessions}) reached. Please retry later.`
        }));
        return;
      }

      try {
        const toolContext: ToolContext = {
          token: auth.token,
          tenantId: auth.claims.tenantId,
          actorId: auth.claims.actorId
        };

        const apiClient = new AeitronApiClient({
          ...config,
          defaultApiKey: auth.token
        });

        const serverInstance = createAeitronMcpServer({
          config,
          client: apiClient,
          authClaims: auth.claims
        });

        const baseMessagesPath = pathname === '/sse' ? '/messages' : '/mcp/messages';
        const messagesPath = wasInQuery && rawToken ? `${baseMessagesPath}?token=${encodeURIComponent(rawToken)}` : baseMessagesPath;
        const transport = new SSEServerTransport(messagesPath, res);

        const session: ActiveSession = {
          sessionId: transport.sessionId,
          transport,
          serverInstance,
          context: toolContext,
          createdAt: new Date(),
          lastActiveAt: Date.now()
        };

        activeSessions.set(transport.sessionId, session);

        res.on('close', async () => {
          activeSessions.delete(transport.sessionId);
          try {
            await serverInstance.server.close();
          } catch {
            // ignore close errors on connection tear-down
          }
        });

        try {
          await serverInstance.server.connect(transport);
        } catch (err: unknown) {
          activeSessions.delete(transport.sessionId);
          try {
            await transport.close();
          } catch {}
          try {
            await serverInstance.server.close();
          } catch {}
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/problem+json' });
            res.end(JSON.stringify({
              type: 'https://aeitron.com/errors/internal-server-error',
              title: 'Internal Server Error',
              status: 500,
              detail: 'Failed to initialize SSE session transport.'
            }));
          } else {
            res.destroy();
          }
        }
      } catch (err: unknown) {
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/problem+json' });
          res.end(JSON.stringify({
            type: 'https://aeitron.com/errors/internal-server-error',
            title: 'Internal Server Error',
            status: 500,
            detail: 'Failed to setup SSE session.'
          }));
        } else {
          res.destroy();
        }
      } finally {
        releaseSessionSlot();
      }
      return;
    }

    // D. JSON-RPC Message Delivery for SSE (/mcp/messages or /messages)
    if (pathname === '/mcp/messages' || pathname === '/messages') {
      if (req.method !== 'POST') {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Method Not Allowed. Use POST for JSON-RPC messages.' }));
        return;
      }

      const sessionId = parsedUrl.searchParams.get('sessionId');
      if (!sessionId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing required "sessionId" query parameter.' }));
        return;
      }

      const session = activeSessions.get(sessionId);
      if (!session) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Session '${sessionId}' not found or has been closed.` }));
        return;
      }

      // Security Check: Strict Authentication & Identity Binding on SSE Messages
      const { token: rawToken } = extractTokenFromRequest(req, parsedUrl);
      if (!rawToken) {
        res.writeHead(401, {
          'Content-Type': 'application/problem+json',
          'WWW-Authenticate': 'Bearer realm="Aeitron MCP"'
        });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/unauthorized',
          title: 'Unauthorized',
          status: 401,
          detail: 'Missing required Authorization bearer token on SSE message post.'
        }));
        return;
      }

      const auth = verifyAuthToken(rawToken, {
        isProduction: config.environment === 'production',
        allowSandbox: config.allowSandbox,
        jwtSecret: config.jwtSecret
      });

      if (!auth.success) {
        res.writeHead(auth.status, {
          'Content-Type': 'application/problem+json',
          'WWW-Authenticate': 'Bearer realm="Aeitron MCP"'
        });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/unauthorized',
          title: auth.code,
          status: auth.status,
          detail: auth.error
        }));
        return;
      }

      if (auth.claims.tenantId !== session.context.tenantId || auth.claims.actorId !== session.context.actorId) {
        res.writeHead(403, { 'Content-Type': 'application/problem+json' });
        res.end(JSON.stringify({
          type: 'https://aeitron.com/errors/forbidden',
          title: 'Forbidden',
          status: 403,
          detail: 'Cross-tenant session access prohibited. Caller identity does not match SSE session owner.'
        }));
        return;
      }

      // Update session activity timestamp to prevent premature idle cleanup
      session.lastActiveAt = Date.now();

      try {
        await session.transport.handlePostMessage(req, res);
      } catch (err: unknown) {
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Error handling message: ${String(err)}` }));
        }
      }
      return;
    }

    // E. All other requests dispatched through Hono router
    honoListener(req, res);
  });

  // 8. Periodic Stale Session Cleanup Timer (Enforces idle session expiration)
  const sweepIntervalMs = Math.min(config.sessionIdleTimeoutMs, 30000);
  const idleCleanupInterval = setInterval(() => {
    const now = Date.now();
    sweepRateLimitBuckets(now);
    for (const [id, session] of streamableSessions.entries()) {
      if (now - session.lastActiveAt > config.sessionIdleTimeoutMs) {
        streamableSessions.delete(id);
        session.transport.close().catch(() => {});
        session.serverInstance.server.close().catch(() => {});
      }
    }

    for (const [id, session] of activeSessions.entries()) {
      if (now - session.lastActiveAt > config.sessionIdleTimeoutMs) {
        activeSessions.delete(id);
        session.transport.close().catch(() => {});
        session.serverInstance.server.close().catch(() => {});
      }
    }
  }, sweepIntervalMs);
  idleCleanupInterval.unref();

  return {
    httpServer,
    app,
    activeSessions,
    get port() {
      const addr = httpServer.address();
      return typeof addr === 'object' && addr !== null ? addr.port : 0;
    },
    close: async () => {
      clearInterval(idleCleanupInterval);

      for (const session of activeSessions.values()) {
        try {
          await session.transport.close();
          await session.serverInstance.server.close();
        } catch {
          // ignore during shutdown
        }
      }
      activeSessions.clear();

      for (const session of streamableSessions.values()) {
        try {
          await session.transport.close();
          await session.serverInstance.server.close();
        } catch {
          // ignore during shutdown
        }
      }
      streamableSessions.clear();

      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
    }
  };
}

// Standalone execution if started directly: node dist/http.js
if (process.argv[1] && process.argv[1].endsWith('http.js')) {
  const port = parseInt(process.env.PORT || '3005', 10);
  const { httpServer } = createMcpHttpServer();

  httpServer.listen(port, () => {
    process.stderr.write(`[aeitron-mcp] Remote Streamable HTTP Server listening on http://localhost:${port}\n`);
    process.stderr.write(`[aeitron-mcp] Streamable HTTP endpoint: http://localhost:${port}/mcp\n`);
    process.stderr.write(`[aeitron-mcp] SSE handshake endpoint:   http://localhost:${port}/mcp/sse\n`);
    process.stderr.write(`[aeitron-mcp] Health endpoint:           http://localhost:${port}/health\n`);
    process.stderr.write(`[aeitron-mcp] JWKS endpoint:             http://localhost:${port}/.well-known/jwks.json\n`);
  });

  const shutdown = async () => {
    process.stderr.write('\n[aeitron-mcp] Gracefully shutting down...\n');
    httpServer.close(() => {
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
