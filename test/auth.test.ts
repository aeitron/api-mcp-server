import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage } from 'node:http';
import { extractTokenFromRequest, verifyAuthToken, getOAuthDiscoveryMetadata } from '../src/auth.js';

describe('OAuth & Token Verification Suite (Phase 2)', () => {
  it('extracts Bearer token from Authorization header', () => {
    const mockReq = {
      headers: {
        authorization: 'Bearer atk_live_tenant42_secretKey123'
      }
    } as unknown as IncomingMessage;

    const url = new URL('http://localhost/mcp/sse');
    const token = extractTokenFromRequest(mockReq, url);
    assert.equal(token, 'atk_live_tenant42_secretKey123');
  });

  it('extracts token from query parameters when header is absent', () => {
    const mockReq = { headers: {} } as unknown as IncomingMessage;
    const url = new URL('http://localhost/mcp/sse?token=atk_sandbox_test_token_88');
    const token = extractTokenFromRequest(mockReq, url);
    assert.equal(token, 'atk_sandbox_test_token_88');
  });

  it('verifies valid sandbox and test API keys', () => {
    const result = verifyAuthToken('atk_sandbox_alpha_1');
    assert.equal(result.success, true);
    if (result.success) {
      assert.equal(result.claims.tier, 'sandbox');
      assert.equal(result.claims.livemode, false);
      assert.ok(result.claims.scopes.includes('account:read'));
      assert.ok(result.claims.scopes.includes('dns:read'));
    }
  });

  it('verifies live production API keys and extracts tenant identity', () => {
    const result = verifyAuthToken('atk_live_customerAcme_8832a');
    assert.equal(result.success, true);
    if (result.success) {
      assert.equal(result.claims.tenantId, 'tenant_customerAcme');
      assert.equal(result.claims.livemode, true);
      assert.ok(result.claims.scopes.includes('dns:write:delete'));
    }
  });

  it('rejects missing or empty token with 401 Unauthorized', () => {
    const result = verifyAuthToken(undefined);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'UNAUTHORIZED');
    }
  });

  it('rejects expired JWT token with 401 TOKEN_EXPIRED', () => {
    // Expired payload with exp = 1000 (year 1970)
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      sub: 'usr_old',
      exp: 1000,
      scopes: ['account:read']
    })).toString('base64url');
    const expiredJwt = `${header}.${payload}.mockSignature`;

    const result = verifyAuthToken(expiredJwt);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'TOKEN_EXPIRED');
    }
  });

  it('enforces required scopes and denies unauthorized permissions with 403 Forbidden', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      sub: 'usr_limited',
      exp: Math.floor(Date.now() / 1000) + 3600,
      scopes: ['account:read'] // Only has read, not delete
    })).toString('base64url');
    const limitedJwt = `${header}.${payload}.mockSignature`;

    const result = verifyAuthToken(limitedJwt, {
      requiredScopes: ['dns:write:delete']
    });

    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 403);
      assert.equal(result.code, 'INSUFFICIENT_SCOPE');
      assert.ok(result.error.includes('dns:write:delete'));
    }
  });

  it('generates compliant RFC 8414 OAuth 2.0 metadata', () => {
    const meta = getOAuthDiscoveryMetadata('https://api.aeitron.com');
    assert.equal(meta.issuer, 'https://api.aeitron.com');
    assert.equal(meta.token_endpoint, 'https://api.aeitron.com/v1/auth/token');
    assert.ok(Array.isArray(meta.scopes_supported));
    assert.ok(Array.isArray(meta.grant_types_supported));
  });
});

