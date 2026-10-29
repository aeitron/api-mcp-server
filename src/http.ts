/**
 * Aeitron MCP Server — Hardened Remote Streamable HTTP (SSE) Server
 * Enforces per-session cryptographic authentication, tool-level RBAC scopes,
 * CORS origin allowlists, and RFC 8414 / RFC 7517 discovery metadata.
 */

import http, { IncomingMessage, ServerResponse } from 'node:http';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getRequestListener } from '@hono/node-server';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { createAeitronMcpServer } from './server.js';
import {
  extractTokenFromRequest,
  verifyAuthToken,
  getOAuthDiscoveryMetadata,
  getJwksMetadata,
  createSignedTestJwt
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

  // 1. Strict CORS Policy
  app.use('*', cors({
    origin: (origin) => {
      if (!origin) return config.corsAllowedOrigins[0] || '*';
      if (config.corsAllowedOrigins.includes('*') || config.corsAllowedOrigins.includes(origin)) {
        return origin;
      }
      return null;
    },
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Tenant-ID'],
    exposeHeaders: ['X-Request-ID', 'X-Session-ID'],
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
      supportedTransports: ['stdio', 'sse'],
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

  // 5. Mock / Local Token Exchange Endpoint for OAuth Testing
  app.post('/v1/auth/token', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    if (body.grant_type === 'client_credentials') {
      const token = createSignedTestJwt({
        sub: body.client_id || 'usr_client_cred',
        tenant_id: 'tenant_client_workspace',
        scopes: ['account:read', 'projects:read', 'dns:read', 'usage:read']
      });
      return c.json({
        access_token: token,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'account:read projects:read dns:read usage:read'
      });
    }
    return c.json({ error: 'unsupported_grant_type' }, 400);
  });

  // 6. Welcome & Discovery
  app.get('/', (c) => {
    return c.json({
      name: 'Aeitron Infrastructure MCP Server',
      description: 'Official Model Context Protocol server connecting AI clients with Aeitron Cloud & Edge Infrastructure',
      version: '1.0.0',
      endpoints: {
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

  // 7. Main Node HTTP Dispatcher
  const httpServer = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const host = req.headers.host || 'localhost';
    const parsedUrl = new URL(req.url || '/', `http://${host}`);
    const pathname = parsedUrl.pathname;

    // A. SSE Handshake (/mcp/sse or /sse)
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

      // Create dedicated client & server instance bound to this verified tenant and scopes
      const apiClient = new AeitronApiClient({
        ...config,
        defaultApiKey: auth.token
      });

      const serverInstance = createAeitronMcpServer({
        config,
        client: apiClient,
        authClaims: auth.claims
      });

      // Target endpoint client should POST messages to
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

    // B. JSON-RPC Message Delivery (/mcp/messages or /messages)
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

    // C. All other requests dispatched through Hono router
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
    process.stderr.write(`[aeitron-mcp] Remote Streamable HTTP (SSE) Server listening on http://localhost:${port}\n`);
    process.stderr.write(`[aeitron-mcp] Handshake endpoint: http://localhost:${port}/mcp/sse\n`);
    process.stderr.write(`[aeitron-mcp] Health endpoint:    http://localhost:${port}/health\n`);
    process.stderr.write(`[aeitron-mcp] JWKS endpoint:      http://localhost:${port}/.well-known/jwks.json\n`);
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
