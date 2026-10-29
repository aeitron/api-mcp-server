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
  extractTokenFromRequest,
  verifyAuthToken,
  getOAuthDiscoveryMetadata,
  getJwksMetadata,
  createSignedTestJwt,
  verifyOAuthClient,
  registerOAuthClientForTesting
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
  const startTime = Date.now();

  // In non-production/test environments, register a default OAuth test client if none exists
  if (config.environment !== 'production') {
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
    allowHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Tenant-ID', 'Mcp-Session-Id', 'Last-Event-ID'],
    exposeHeaders: ['X-Request-ID', 'X-Session-ID', 'Mcp-Session-Id'],
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
      activeSessions: activeSessions.size,
      mockFallbackEnabled: config.mockFallback
    });
  });

  app.get('/ready', (c) => {
    return c.json({
      ready: true,
      service: 'aeitron-mcp-server',
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
    const token = createSignedTestJwt({
      sub: client.actorId,
      tenant_id: client.tenantId,
      scopes: client.scopes
    }, config.jwtSecret);

    return c.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: client.scopes.join(' ')
    });
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
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID, X-Tenant-ID, Mcp-Session-Id, Last-Event-ID');
        res.setHeader('Access-Control-Expose-Headers', 'X-Request-ID, X-Session-ID, Mcp-Session-Id');
        res.setHeader('Access-Control-Max-Age', '86400');
      } else if (config.environment === 'production') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `CORS policy error: Origin '${origin}' is not allowed in production.` }));
        return;
      }
    }

    // Handle preflight OPTIONS requests across all endpoints
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // B. Modern Streamable HTTP Endpoint (/mcp)
    if (pathname === '/mcp' && req.method === 'POST') {
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

      // Initialize dedicated server and streamable transport
      const apiClient = new AeitronApiClient({
        ...config,
        defaultApiKey: auth.token
      });

      const serverInstance = createAeitronMcpServer({
        config,
        client: apiClient,
        authClaims: auth.claims
      });

      const streamableTransport = new StreamableHTTPServerTransport();
      await serverInstance.server.connect(streamableTransport);
      await streamableTransport.handleRequest(req, res);
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
      if (wasInQuery && config.environment === 'production') {
        process.stderr.write('[aeitron-mcp][WARN] Token provided via query parameter in production. Authorization: Bearer <token> header is strongly recommended.\n');
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

      const messagesPath = pathname === '/sse' ? '/messages' : '/mcp/messages';
      const transport = new SSEServerTransport(messagesPath, res);

      const session: ActiveSession = {
        sessionId: transport.sessionId,
        transport,
        serverInstance,
        context: toolContext,
        createdAt: new Date()
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
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Failed to initialize SSE session: ${String(err)}` }));
        }
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

  return {
    httpServer,
    app,
    activeSessions,
    get port() {
      const addr = httpServer.address();
      return typeof addr === 'object' && addr !== null ? addr.port : 0;
    },
    close: async () => {
      for (const session of activeSessions.values()) {
        try {
          await session.transport.close();
          await session.serverInstance.server.close();
        } catch {
          // ignore during shutdown
        }
      }
      activeSessions.clear();

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
