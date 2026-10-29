import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createMcpHttpServer, McpHttpServerInstance } from '../src/http.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';

describe('Remote Streamable HTTP & SSE Transport Suite (Phase 2)', () => {
  let serverInstance: McpHttpServerInstance;
  let baseUrl: string;

  before(async () => {
    serverInstance = createMcpHttpServer({
      environment: 'development',
      mockFallback: true
    });

    await new Promise<void>((resolve) => {
      serverInstance.httpServer.listen(0, '127.0.0.1', () => {
        const addr = serverInstance.httpServer.address();
        const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await serverInstance.close();
  });

  it('1. GET /health: returns service status, transports, and active session counts', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = await res.json() as { status: string; service: string; activeSessions: number };
    assert.equal(body.status, 'ok');
    assert.equal(body.service, 'aeitron-mcp-server');
    assert.equal(typeof body.activeSessions, 'number');
  });

  it('2. GET /ready: returns readiness probe including modern streamable-http transport', async () => {
    const res = await fetch(`${baseUrl}/ready`);
    assert.equal(res.status, 200);
    const body = await res.json() as { ready: boolean; supportedTransports: string[] };
    assert.equal(body.ready, true);
    assert.ok(body.supportedTransports.includes('streamable-http'));
    assert.ok(body.supportedTransports.includes('sse'));
  });

  it('3. GET /.well-known/oauth-authorization-server: returns OAuth metadata with client_credentials', async () => {
    const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    assert.equal(res.status, 200);
    const meta = await res.json() as { token_endpoint: string; scopes_supported: string[]; grant_types_supported: string[] };
    assert.ok(meta.token_endpoint.includes('/v1/auth/token'));
    assert.ok(meta.scopes_supported.includes('dns:read'));
    assert.deepEqual(meta.grant_types_supported, ['client_credentials']);
  });

  it('4. GET /.well-known/jwks.json: returns compliant JWKS public key metadata', async () => {
    const res = await fetch(`${baseUrl}/.well-known/jwks.json`);
    assert.equal(res.status, 200);
    const body = await res.json() as { keys: Array<{ kty: string; alg: string }> };
    assert.ok(Array.isArray(body.keys));
    assert.equal(body.keys[0].alg, 'HS256');
  });

  it('5. POST /v1/auth/token: strictly rejects unauthenticated callers with 401 invalid_client', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials'
        // Missing client_id and client_secret!
      })
    });
    assert.equal(res.status, 401);
    const body = await res.json() as { error: string };
    assert.equal(body.error, 'invalid_client');
  });

  it('6. POST /v1/auth/token: rejects invalid client_secret with 401 unauthorized_client', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        client_id: 'aeitron_test_client_id',
        client_secret: 'wrong_unauthorized_secret'
      })
    });
    assert.equal(res.status, 401);
    const body = await res.json() as { error: string };
    assert.equal(body.error, 'unauthorized_client');
  });

  it('7. POST /v1/auth/token: authenticates valid client credentials and issues signed JWT', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        client_id: 'aeitron_test_client_id',
        client_secret: 'secret_test_key_889'
      })
    });
    assert.equal(res.status, 200);
    const body = await res.json() as { access_token: string; token_type: string; expires_in: number };
    assert.equal(body.token_type, 'Bearer');
    assert.ok(typeof body.access_token === 'string' && body.access_token.startsWith('eyJ'));
    assert.equal(body.expires_in, 3600);
  });

  it('8. CORS Preflight: handles OPTIONS requests on /mcp/sse and sets standard CORS headers', async () => {
    const res = await fetch(`${baseUrl}/mcp/sse`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://chatgpt.com',
        'Access-Control-Request-Method': 'GET'
      }
    });
    assert.equal(res.status, 204);
    assert.ok(res.headers.get('access-control-allow-origin'));
    assert.ok(res.headers.get('access-control-allow-methods'));
  });

  it('9. CORS Preflight: handles OPTIONS requests on /mcp', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://claude.ai',
        'Access-Control-Request-Method': 'POST'
      }
    });
    assert.equal(res.status, 204);
    assert.ok(res.headers.get('access-control-allow-origin'));
  });

  it('10. Security Gate: rejects unauthenticated SSE connection with 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/mcp/sse`);
    assert.equal(res.status, 401);
    const problem = await res.json() as { type: string; status: number };
    assert.equal(problem.status, 401);
    assert.ok(problem.type.includes('unauthorized'));
  });

  it('11. Remote MCP over SSE: connects client, discovers tools, and calls tool successfully', async () => {
    const sseUrl = new URL(`${baseUrl}/mcp/sse?token=atk_sandbox_live_e2e_test`);
    const transport = new SSEClientTransport(sseUrl);

    const client = new Client({
      name: 'aeitron-remote-test-client',
      version: '1.0.0'
    });

    await client.connect(transport);

    const toolList = await client.listTools();
    const names = toolList.tools.map((t) => t.name);
    assert.ok(names.includes('get_account'));
    assert.ok(names.includes('get_dns_records'));

    const result = await client.callTool({
      name: 'get_account',
      arguments: {}
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('Aeitron Account Overview'));

    assert.equal(serverInstance.activeSessions.size, 1);
    await client.close();
  });

  it('12. POST /mcp/messages: rejects unknown or expired session IDs with 404', async () => {
    const res = await fetch(`${baseUrl}/mcp/messages?sessionId=non_existent_session_id`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 1 })
    });

    assert.equal(res.status, 404);
    const body = await res.json() as { error: string };
    assert.ok(body.error.includes('not found'));
  });
});
