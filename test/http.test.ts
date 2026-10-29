import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createMcpHttpServer, McpHttpServerInstance } from '../src/http.js';
import { createSignedTestJwt } from '../src/auth.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
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

  it('4. GET /.well-known/jwks.json: returns compliant JWKS public key metadata with RSA public key', async () => {
    const res = await fetch(`${baseUrl}/.well-known/jwks.json`);
    assert.equal(res.status, 200);
    const body = await res.json() as { keys: Array<{ kty: string; alg: string; n: string; e: string }> };
    assert.ok(Array.isArray(body.keys));
    assert.equal(body.keys[0].kty, 'RSA');
    assert.equal(body.keys[0].alg, 'RS256');
    assert.ok(typeof body.keys[0].n === 'string');
    assert.ok(typeof body.keys[0].e === 'string');
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

    // Verify token is signed with RS256 and contains matching kid in header
    const [hB64, pB64] = body.access_token.split('.');
    const header = JSON.parse(Buffer.from(hB64, 'base64url').toString('utf-8')) as { alg: string; kid: string };
    assert.equal(header.alg, 'RS256', 'OAuth token must be signed with RS256');
    assert.equal(header.kid, 'aeitron-mcp-rsa-2026-v1', 'OAuth token kid must match active JWKS key');

    // Verify token verifies against JWKS metadata
    const jwksRes = await fetch(`${baseUrl}/.well-known/jwks.json`);
    const jwks = await jwksRes.json() as { keys: Array<{ kid: string; alg: string; kty: string }> };
    assert.ok(jwks.keys.some((k) => k.kid === header.kid && k.alg === 'RS256' && k.kty === 'RSA'));
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

  it('13. Streamable HTTP Round-Trip: connects client over POST /mcp and executes complete tools/list and tools/call workflow', async () => {
    const mcpUrl = new URL(`${baseUrl}/mcp`);
    const transport = new StreamableHTTPClientTransport(mcpUrl, {
      requestInit: {
        headers: {
          'Authorization': 'Bearer atk_sandbox_live_e2e_test'
        }
      }
    });

    const client = new Client({
      name: 'aeitron-streamable-test-client',
      version: '1.0.0'
    });

    await client.connect(transport);

    // Verify tool discovery over Streamable HTTP
    const toolList = await client.listTools();
    const names = toolList.tools.map((t) => t.name);
    assert.ok(names.includes('get_account'));
    assert.ok(names.includes('get_dns_records'));

    // Verify tool execution over Streamable HTTP
    const result = await client.callTool({
      name: 'get_account',
      arguments: {}
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('Aeitron Account Overview'));

    await client.close();
  });

  it('14. CORS Preflight & Protocol Headers: validates MCP-Protocol-Version in preflight headers', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://chatgpt.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type, Authorization, MCP-Protocol-Version'
      }
    });

    assert.equal(res.status, 204);
    const allowHeaders = res.headers.get('access-control-allow-headers') || '';
    assert.ok(allowHeaders.includes('MCP-Protocol-Version'));
    assert.ok(allowHeaders.includes('Mcp-Method'));
  });

  it('15. Security Gate: rejects unauthenticated Streamable HTTP connection with 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1 })
    });

    assert.equal(res.status, 401);
    const problem = await res.json() as { type: string; status: number };
    assert.equal(problem.status, 401);
    assert.ok(problem.type.includes('unauthorized'));
  });

  it('16. Cross-Tenant Protection: rejects session access when token tenant does not match session owner', async () => {
    // 1. Tenant A creates a valid session
    const tenantAToken = 'atk_sandbox_tenant_a_token';
    const initRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Authorization': `Bearer ${tenantAToken}`
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'tenant-a-client', version: '1.0' }
        },
        id: 1
      })
    });

    assert.equal(initRes.status, 200);
    const sessionId = initRes.headers.get('mcp-session-id');
    assert.ok(sessionId, 'Server must return Mcp-Session-Id header');

    // 2. Tenant B obtains a valid JWT with a different tenant ID
    const { createSignedTestJwt } = await import('../src/auth.js');
    const tenantBJwt = createSignedTestJwt({
      sub: 'usr_tenant_b_attacker',
      tenant_id: 'tenant_different_b',
      scopes: ['account:read', 'dns:read']
    });

    // 3. Tenant B attempts to call tools on Tenant A's session -> MUST BE STRICTLY 403 FORBIDDEN
    const hijackRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Mcp-Session-Id': sessionId,
        'Authorization': `Bearer ${tenantBJwt}`
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/list',
        id: 2
      })
    });

    assert.equal(hijackRes.status, 403);
    const hijackBody = await hijackRes.json() as { status: number; detail: string };
    assert.equal(hijackBody.status, 403);
    assert.ok(hijackBody.detail.includes('Cross-tenant session access prohibited'));

    // 4. Tenant B attempts to delete Tenant A's session -> MUST ALSO BE 403 FORBIDDEN
    const deleteRes = await fetch(`${baseUrl}/mcp`, {
      method: 'DELETE',
      headers: {
        'Mcp-Session-Id': sessionId,
        'Authorization': `Bearer ${tenantBJwt}`
      }
    });

    assert.equal(deleteRes.status, 403);
  });

  it('17. Human Operator DNS Deletion Approval: authorizes request via POST /v1/dns/approve-deletion', async () => {
    const { createDnsDeletionRequest, createSignedTestJwt } = await import('../src/auth.js');
    
    // Create pending deletion request
    const req = createDnsDeletionRequest('tenant_customerAcme', 'usr_agent_01', 'aeitron.com', 'rec_cname_999');
    assert.ok(req.requestId.startsWith('del_req_'));

    // Operator with insufficient scopes attempts approval -> 403 Forbidden
    const unprivilegedToken = createSignedTestJwt({
      sub: 'usr_readonly_op',
      tenant_id: 'tenant_customerAcme',
      scopes: ['account:read', 'dns:read'] // missing dns:write:delete
    });

    const unprivRes = await fetch(`${baseUrl}/v1/dns/approve-deletion`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${unprivilegedToken}`
      },
      body: JSON.stringify({ requestId: req.requestId })
    });
    assert.equal(unprivRes.status, 403);

    // Operator with valid dns:delete:approve scope approves deletion request -> 200 OK with approvalToken
    const operatorToken = createSignedTestJwt({
      sub: 'usr_authorized_operator',
      tenant_id: 'tenant_customerAcme',
      scopes: ['dns:delete:approve']
    });

    const approveRes = await fetch(`${baseUrl}/v1/dns/approve-deletion`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${operatorToken}`
      },
      body: JSON.stringify({ requestId: req.requestId })
    });

    assert.equal(approveRes.status, 200);
    const approveBody = await approveRes.json() as { success: boolean; approvalToken: string; requestId: string };
    assert.equal(approveBody.success, true);
    assert.equal(approveBody.requestId, req.requestId);
    assert.ok(approveBody.approvalToken.startsWith('del_tok_'));
  });

  it('18. Session Capacity Guard: rejects new session creation when maxActiveSessions is reached', async () => {
    // Create server with capacity limit of 1
    const limitedServer = createMcpHttpServer({
      environment: 'development',
      maxActiveSessions: 1
    });

    await new Promise<void>((resolve) => {
      limitedServer.httpServer.listen(0, '127.0.0.1', () => resolve());
    });
    const limitedAddr = limitedServer.httpServer.address();
    const limitedPort = typeof limitedAddr === 'object' && limitedAddr !== null ? limitedAddr.port : 0;
    const limitedBaseUrl = `http://127.0.0.1:${limitedPort}`;

    try {
      // First session succeeds
      const res1 = await fetch(`${limitedBaseUrl}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/event-stream',
          'Authorization': 'Bearer atk_sandbox_session_1'
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'initialize',
          params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'c1', version: '1.0' } },
          id: 1
        })
      });
      assert.equal(res1.status, 200);

      // Second session must be rejected with 503 Service Unavailable
      const res2 = await fetch(`${limitedBaseUrl}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/event-stream',
          'Authorization': 'Bearer atk_sandbox_session_2'
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'initialize',
          params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'c2', version: '1.0' } },
          id: 1
        })
      });
      assert.equal(res2.status, 503);
      const res2Body = await res2.json() as { status: number; title: string };
      assert.equal(res2Body.status, 503);
      assert.equal(res2Body.title, 'Service Unavailable');

      // Third session via SSE handshake must ALSO be rejected with 503 Service Unavailable
      const res3 = await fetch(`${limitedBaseUrl}/mcp/sse`, {
        method: 'GET',
        headers: {
          'Accept': 'text/event-stream',
          'Authorization': 'Bearer atk_sandbox_session_3'
        }
      });
      assert.equal(res3.status, 503);
      const res3Body = await res3.json() as { status: number; title: string };
      assert.equal(res3Body.status, 503);
      assert.equal(res3Body.title, 'Service Unavailable');
    } finally {
      await limitedServer.close();
    }
  });

  it('19. Session Idle Timeout: periodically sweeps and terminates idle sessions', async () => {
    const idleServer = createMcpHttpServer({
      environment: 'development',
      sessionIdleTimeoutMs: 25 // 25ms timeout
    });

    await new Promise<void>((resolve) => {
      idleServer.httpServer.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = idleServer.httpServer.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    const idleBaseUrl = `http://127.0.0.1:${port}`;

    try {
      const initRes = await fetch(`${idleBaseUrl}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/event-stream',
          'Authorization': 'Bearer atk_sandbox_idle_test'
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'initialize',
          params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'idle-client', version: '1.0' } },
          id: 1
        })
      });
      assert.equal(initRes.status, 200);
      const sessionId = initRes.headers.get('mcp-session-id')!;
      assert.ok(sessionId);

      // Wait 60ms to let idle timeout expire (25ms timeout)
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Attempting to use the idle session must fail with 404 session not found or expired
      const followUpRes = await fetch(`${idleBaseUrl}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/event-stream',
          'Mcp-Session-Id': sessionId,
          'Authorization': 'Bearer atk_sandbox_idle_test'
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'tools/list',
          id: 2
        })
      });

      assert.equal(followUpRes.status, 404);
    } finally {
      await idleServer.close();
    }
  });

  it('20. Legacy SSE Security: rejects message post without authorization token with 401', async () => {
    // 1. Establish SSE session with valid token
    const sseRes = await fetch(`${baseUrl}/mcp/sse`, {
      headers: { 'Authorization': 'Bearer atk_sandbox_live_e2e_test' }
    });
    assert.equal(sseRes.status, 200);

    // Read initial endpoint event to extract sessionId
    const reader = sseRes.body!.getReader();
    const decoder = new TextDecoder();
    let endpointData = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      endpointData += decoder.decode(value, { stream: true });
      if (endpointData.includes('event: endpoint')) break;
    }
    const match = endpointData.match(/sessionId=([a-f0-9\-]+)/);
    assert.ok(match, 'Expected sessionId in SSE endpoint event');
    const sessionId = match[1];

    // Attempt to post message without Authorization token -> must return 401
    const postRes = await fetch(`${baseUrl}/mcp/messages?sessionId=${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 1 })
    });
    assert.equal(postRes.status, 401);
    const body = await postRes.json() as { type: string; status: number };
    assert.equal(body.status, 401);

    reader.cancel().catch(() => {});
  });

  it('21. Legacy SSE Security: rejects invalid token with 401 Unauthorized', async () => {
    const sseRes = await fetch(`${baseUrl}/mcp/sse`, {
      headers: { 'Authorization': 'Bearer atk_sandbox_live_e2e_test' }
    });
    assert.equal(sseRes.status, 200);

    const reader = sseRes.body!.getReader();
    const decoder = new TextDecoder();
    let endpointData = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      endpointData += decoder.decode(value, { stream: true });
      if (endpointData.includes('event: endpoint')) break;
    }
    const match = endpointData.match(/sessionId=([a-f0-9\-]+)/);
    assert.ok(match);
    const sessionId = match[1];

    const postRes = await fetch(`${baseUrl}/mcp/messages?sessionId=${sessionId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer invalid_forged_token_xyz'
      },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 1 })
    });
    assert.equal(postRes.status, 401);

    reader.cancel().catch(() => {});
  });

  it('22. Legacy SSE Security: rejects cross-tenant token on active SSE session with 403 Forbidden', async () => {
    // Session owner has tenant_test_workspace
    const sseRes = await fetch(`${baseUrl}/mcp/sse`, {
      headers: { 'Authorization': 'Bearer atk_sandbox_live_e2e_test' }
    });
    assert.equal(sseRes.status, 200);

    const reader = sseRes.body!.getReader();
    const decoder = new TextDecoder();
    let endpointData = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      endpointData += decoder.decode(value, { stream: true });
      if (endpointData.includes('event: endpoint')) break;
    }
    const match = endpointData.match(/sessionId=([a-f0-9\-]+)/);
    assert.ok(match);
    const sessionId = match[1];

    // Attacker token from a different tenant
    const attackerToken = createSignedTestJwt({
      tenant_id: 'tenant_malicious_competitor',
      sub: 'usr_attacker_99',
      scopes: ['account:read', 'dns:read']
    });

    const postRes = await fetch(`${baseUrl}/mcp/messages?sessionId=${sessionId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${attackerToken}`
      },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 1 })
    });
    assert.equal(postRes.status, 403);
    const body = await postRes.json() as { type: string; status: number };
    assert.equal(body.status, 403);

    reader.cancel().catch(() => {});
  });

  it('23. Legacy SSE Security: rejects same-tenant different actor token on active SSE session with 403 Forbidden', async () => {
    const sseRes = await fetch(`${baseUrl}/mcp/sse`, {
      headers: { 'Authorization': 'Bearer atk_sandbox_live_e2e_test' }
    });
    assert.equal(sseRes.status, 200);

    const reader = sseRes.body!.getReader();
    const decoder = new TextDecoder();
    let endpointData = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      endpointData += decoder.decode(value, { stream: true });
      if (endpointData.includes('event: endpoint')) break;
    }
    const match = endpointData.match(/sessionId=([a-f0-9\-]+)/);
    assert.ok(match);
    const sessionId = match[1];

    // Same tenant ('tenant_test_workspace'), but DIFFERENT actor ('usr_different_colleague')
    const differentActorToken = createSignedTestJwt({
      tenant_id: 'tenant_test_workspace',
      sub: 'usr_different_colleague',
      scopes: ['account:read', 'dns:read']
    });

    const postRes = await fetch(`${baseUrl}/mcp/messages?sessionId=${sessionId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${differentActorToken}`
      },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'ping', id: 1 })
    });
    assert.equal(postRes.status, 403);

    reader.cancel().catch(() => {});
  });

  it('24. DNS Deletion Request Endpoints: strictly require operator scope and redact approvalToken', async () => {
    // 1. Non-operator caller lacking dns:write:delete scope
    const readOnlyToken = createSignedTestJwt({
      tenant_id: 'tenant_test_workspace',
      sub: 'usr_readonly_analyst',
      scopes: ['account:read', 'dns:read']
    });

    const getForbidden = await fetch(`${baseUrl}/v1/dns/deletion-requests`, {
      headers: { 'Authorization': `Bearer ${readOnlyToken}` }
    });
    assert.equal(getForbidden.status, 403);

    // 2. Operator caller with dns:write:delete scope
    const operatorToken = createSignedTestJwt({
      tenant_id: 'tenant_test_workspace',
      sub: 'usr_operator_admin',
      scopes: ['dns:write:delete']
    });

    const getOk = await fetch(`${baseUrl}/v1/dns/deletion-requests`, {
      headers: { 'Authorization': `Bearer ${operatorToken}` }
    });
    assert.equal(getOk.status, 200);
    const data = await getOk.json() as { requests: Array<Record<string, unknown>> };
    assert.ok(Array.isArray(data.requests));

    // Verify redaction: approvalToken must NEVER be exposed in the list endpoint
    for (const req of data.requests) {
      assert.strictEqual(req['approvalToken'], undefined, 'approvalToken MUST NOT be present in read DTO');
    }
  });
});
