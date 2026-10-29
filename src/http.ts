/**
 * Aeitron MCP Server — Remote Streamable HTTP (SSE) Server
 * Exposes SSE and JSON-RPC message endpoints for Claude, ChatGPT, and remote AI agents.
 */

import http, { IncomingMessage, ServerResponse } from 'node:http';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getRequestListener } from '@hono/node-server';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { createAeitronMcpServer } from './server.js';
import { extractTokenFromRequest, verifyAuthToken, getOAuthDiscoveryMetadata } from './auth.js';
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

  // 1. CORS Policy
  app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Tenant-ID'],
    exposeHeaders: ['X-Request-ID', 'X-Session-ID'],
    maxAge: 86400
  }));

  // 2. Health & Readiness
  app.get('/health', (c) => {
    return c.json({
      status: 'ok',
      service: 'aeitron-mcp-server',
      version: '0.1.0',
      environment: config.environment,
      uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
      activeSessions: activeSessions.size
    });
  });

  app.get('/ready', (c) => {
    return c.json({
      ready: true,
      service: 'aeitron-mcp-server',
      supportedTransports: ['stdio', 'sse'],
      toolsAvailable: ['get_account', 'list_projects', 'get_project', 'get_dns_records', 'get_usage']
    });
  });

  // 3. OAuth 2.0 Authorization Server Metadata (RFC 8414)
  const oauthHandler = (c: { json: (data: unknown) => Response }) => {
    return c.json(getOAuthDiscoveryMetadata(config.apiBaseUrl));
  };
  app.get('/.well-known/oauth-authorization-server', oauthHandler);
  app.get('/mcp/.well-known/oauth-authorization-server', oauthHandler);

  // 4. Welcome & Discovery
  app.get('/', (c) => {
    return c.json({
      name: 'Aeitron Infrastructure MCP Server',
      description: 'Official Model Context Protocol server connecting AI clients with Aeitron Cloud & Edge Infrastructure',
      endpoints: {
        sse: '/mcp/sse',
        messages: '/mcp/messages?sessionId={id}',
        health: '/health',
        ready: '/ready',
        oauthMetadata: '/.well-known/oauth-authorization-server'
      },
      documentation: 'https://docs.aeitron.com/mcp'
    });
  });

  const honoListener = getRequestListener(app.fetch);

  // 5. Main Node HTTP Dispatcher
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
      const rawToken = extractTokenFromRequest(req, parsedUrl);
      const auth = verifyAuthToken(rawToken, { isProduction: config.environment === 'production' });

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

      // Create dedicated client & server instance bound to this tenant context
      const apiClient = new AeitronApiClient({
        ...config,
        defaultApiKey: auth.token
      });

      const serverInstance = createAeitronMcpServer({
        config,
        client: apiClient
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
  const { httpServer, activeSessions } = createMcpHttpServer();

  httpServer.listen(port, () => {
    process.stderr.write(`[aeitron-mcp] Remote Streamable HTTP (SSE) Server listening on http://localhost:${port}\n`);
    process.stderr.write(`[aeitron-mcp] Handshake endpoint: http://localhost:${port}/mcp/sse\n`);
    process.stderr.write(`[aeitron-mcp] Health endpoint:    http://localhost:${port}/health\n`);
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

