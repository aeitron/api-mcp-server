import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createMcpHttpServer, McpHttpServerInstance } from '../src/http.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';

describe('Remote Streamable HTTP (SSE) Transport Suite (Phase 2)', () => {
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

  it('1. GET /health: returns service status and active session counts', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = await res.json() as { status: string; service: string; activeSessions: number };
    assert.equal(body.status, 'ok');
    assert.equal(body.service, 'aeitron-mcp-server');
    assert.equal(typeof body.activeSessions, 'number');
  });

  it('2. GET /ready: returns readiness probe and supported transports', async () => {
    const res = await fetch(`${baseUrl}/ready`);
    assert.equal(res.status, 200);
    const body = await res.json() as { ready: boolean; supportedTransports: string[] };
    assert.equal(body.ready, true);
    assert.ok(body.supportedTransports.includes('sse'));
  });

  it('3. GET /.well-known/oauth-authorization-server: returns OAuth metadata', async () => {
    const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    assert.equal(res.status, 200);
    const meta = await res.json() as { token_endpoint: string; scopes_supported: string[] };
    assert.ok(meta.token_endpoint.includes('/v1/auth/token'));
    assert.ok(meta.scopes_supported.includes('dns:read'));
  });

  it('4. Security Gate: rejects unauthenticated SSE connection with 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/mcp/sse`);
    assert.equal(res.status, 401);
    const problem = await res.json() as { type: string; status: number };
    assert.equal(problem.status, 401);
    assert.ok(problem.type.includes('unauthorized'));
  });

  it('5. Remote MCP over SSE: connects client, discovers tools, and calls tool successfully', async () => {
    // Authenticate via query param (standard browser EventSource pattern)
    const sseUrl = new URL(`${baseUrl}/mcp/sse?token=atk_sandbox_live_e2e_test`);
    const transport = new SSEClientTransport(sseUrl);

    const client = new Client({
      name: 'aeitron-remote-test-client',
      version: '1.0.0'
    });

    await client.connect(transport);

    // Verify tool discovery
    const toolList = await client.listTools();
    const names = toolList.tools.map((t) => t.name);
    assert.ok(names.includes('get_account'));
    assert.ok(names.includes('get_dns_records'));

    // Verify calling get_account over remote SSE
    const result = await client.callTool({
      name: 'get_account',
      arguments: {}
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('Aeitron Account Overview'));

    // Verify session was registered in active sessions map
    assert.equal(serverInstance.activeSessions.size, 1);

    await client.close();
  });

  it('6. POST /mcp/messages: rejects unknown or expired session IDs with 404', async () => {
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

