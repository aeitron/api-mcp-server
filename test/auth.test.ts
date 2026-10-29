import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage } from 'node:http';
import {
  extractTokenFromRequest,
  verifyAuthToken,
  checkToolAuthorization,
  createSignedTestJwt,
  getOAuthDiscoveryMetadata,
  getJwksMetadata
} from '../src/auth.js';

describe('OAuth & Cryptographic Token Verification Suite', () => {
  it('extracts Bearer token from Authorization header and marks wasInQuery=false', () => {
    const mockReq = {
      headers: {
        authorization: 'Bearer atk_live_customerAcme_8832asecurekey'
      }
    } as unknown as IncomingMessage;

    const url = new URL('http://localhost/mcp/sse');
    const result = extractTokenFromRequest(mockReq, url);
    assert.equal(result.token, 'atk_live_customerAcme_8832asecurekey');
    assert.equal(result.wasInQuery, false);
  });

  it('extracts token from query parameters and marks wasInQuery=true for audit logging', () => {
    const mockReq = { headers: {} } as unknown as IncomingMessage;
    const url = new URL('http://localhost/mcp/sse?token=atk_sandbox_test_token_88');
    const result = extractTokenFromRequest(mockReq, url);
    assert.equal(result.token, 'atk_sandbox_test_token_88');
    assert.equal(result.wasInQuery, true);
  });

  it('verifies valid sandbox key in non-production environment', () => {
    const result = verifyAuthToken('atk_sandbox_alpha_1', { isProduction: false, allowSandbox: true });
    assert.equal(result.success, true);
    if (result.success) {
      assert.equal(result.claims.tier, 'sandbox');
      assert.equal(result.claims.livemode, false);
      assert.ok(result.claims.scopes.includes('account:read'));
      assert.ok(result.claims.scopes.includes('dns:read'));
    }
  });

  it('strictly rejects sandbox key in production environment with 401 SANDBOX_DISABLED_IN_PROD', () => {
    const result = verifyAuthToken('atk_sandbox_alpha_1', { isProduction: true, allowSandbox: false });
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'SANDBOX_DISABLED_IN_PROD');
    }
  });

  it('verifies authoritative live API key against cryptographic hashed registry', () => {
    const result = verifyAuthToken('atk_live_customerAcme_8832asecurekey');
    assert.equal(result.success, true);
    if (result.success) {
      assert.equal(result.claims.tenantId, 'tenant_customerAcme');
      assert.equal(result.claims.actorId, 'usr_live_acme_admin');
      assert.equal(result.claims.livemode, true);
      assert.ok(result.claims.scopes.includes('dns:write:delete'));
    }
  });

  it('strictly rejects fake unverified atk_live_ keys with 401 INVALID_CREDENTIALS', () => {
    const result = verifyAuthToken('atk_live_unregistered_attacker_key_999');
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'INVALID_CREDENTIALS');
    }
  });

  it('rejects missing or empty token with 401 UNAUTHORIZED', () => {
    const result = verifyAuthToken(undefined);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'UNAUTHORIZED');
    }
  });

  it('verifies cryptographically signed valid JWT with HMAC-SHA256 signature', () => {
    const validJwt = createSignedTestJwt({
      sub: 'usr_valid_subscriber',
      org_id: 'org_acme_corp',
      scopes: ['account:read', 'dns:read']
    });

    const result = verifyAuthToken(validJwt);
    assert.equal(result.success, true);
    if (result.success) {
      assert.equal(result.claims.actorId, 'usr_valid_subscriber');
      assert.equal(result.claims.tenantId, 'org_acme_corp');
      assert.ok(result.claims.scopes.includes('account:read'));
    }
  });

  it('rejects forged JWT signature with 401 INVALID_SIGNATURE', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      sub: 'usr_attacker',
      exp: Math.floor(Date.now() / 1000) + 3600,
      scopes: ['dns:write:delete']
    })).toString('base64url');
    const forgedJwt = `${header}.${payload}.forgedInvalidSignatureHere`;

    const result = verifyAuthToken(forgedJwt);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'INVALID_SIGNATURE');
    }
  });

  it('rejects expired JWT token with 401 TOKEN_EXPIRED', () => {
    const expiredJwt = createSignedTestJwt({
      sub: 'usr_expired',
      exp: 1000 // Year 1970
    });

    const result = verifyAuthToken(expiredJwt);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'TOKEN_EXPIRED');
    }
  });

  it('enforces required scopes and denies unauthorized permissions with 403 INSUFFICIENT_SCOPE', () => {
    const limitedJwt = createSignedTestJwt({
      sub: 'usr_limited',
      scopes: ['account:read']
    });

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

  it('enforces granular tool-level authorization via checkToolAuthorization', () => {
    // Unauthenticated caller
    const deniedNoAuth = checkToolAuthorization('delete_dns_record', undefined);
    assert.equal(deniedNoAuth.authorized, false);
    assert.ok(deniedNoAuth.error?.includes('Authentication required'));

    // Caller lacking dns:write:delete
    const deniedScope = checkToolAuthorization('delete_dns_record', {
      actorId: 'usr_test',
      tenantId: 'tenant_test',
      tier: 'developer',
      scopes: ['account:read', 'dns:read'],
      livemode: true
    });
    assert.equal(deniedScope.authorized, false);
    assert.ok(deniedScope.error?.includes('Forbidden'));

    // Authorized caller
    const allowed = checkToolAuthorization('delete_dns_record', {
      actorId: 'usr_admin',
      tenantId: 'tenant_test',
      tier: 'enterprise',
      scopes: ['dns:write:delete'],
      livemode: true
    });
    assert.equal(allowed.authorized, true);
  });

  it('generates compliant RFC 8414 OAuth 2.0 metadata', () => {
    const meta = getOAuthDiscoveryMetadata('https://api.aeitron.com');
    assert.equal(meta.issuer, 'https://api.aeitron.com');
    assert.equal(meta.token_endpoint, 'https://api.aeitron.com/v1/auth/token');
    assert.ok(Array.isArray(meta.scopes_supported));
    assert.ok(Array.isArray(meta.grant_types_supported));
  });

  it('returns compliant RFC 7517 JWKS metadata', () => {
    const jwks = getJwksMetadata();
    assert.ok(Array.isArray(jwks.keys));
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].kty, 'oct');
    assert.equal(jwks.keys[0].alg, 'HS256');
  });
});
