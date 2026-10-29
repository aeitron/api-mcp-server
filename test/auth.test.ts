import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage } from 'node:http';
import crypto from 'node:crypto';
import {
  extractTokenFromRequest,
  verifyAuthToken,
  checkToolAuthorization,
  createSignedTestJwt,
  getOAuthDiscoveryMetadata,
  getJwksMetadata,
  registerAuthoritativeKeyForTesting,
  clearTestRegistries,
  loadAuthoritativeKeysFromEnv,
  issueDnsDeletionChallenge,
  verifyDnsDeletionChallenge
} from '../src/auth.js';

describe('OAuth & Cryptographic Token Verification Suite', () => {
  beforeEach(() => {
    clearTestRegistries();
  });

  it('extracts Bearer token from Authorization header and marks wasInQuery=false', () => {
    const mockReq = {
      headers: {
        authorization: 'Bearer atk_live_test_sample_key_123'
      }
    } as unknown as IncomingMessage;

    const url = new URL('http://localhost/mcp/sse');
    const result = extractTokenFromRequest(mockReq, url);
    assert.equal(result.token, 'atk_live_test_sample_key_123');
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

  it('strictly rejects previously hardcoded test key in clean registry with 401 INVALID_CREDENTIALS', () => {
    // Zero hardcoded keys in source code!
    const result = verifyAuthToken('atk_live_customerAcme_8832asecurekey');
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'INVALID_CREDENTIALS');
    }
  });

  it('dynamically loads authoritative keys from AEITRON_API_KEYS environment format', () => {
    loadAuthoritativeKeysFromEnv('atk_live_env_loaded_key:tenant_env_01:usr_env_admin:enterprise:account:read+dns:write:delete');
    const result = verifyAuthToken('atk_live_env_loaded_key');
    assert.equal(result.success, true);
    if (result.success) {
      assert.equal(result.claims.tenantId, 'tenant_env_01');
      assert.equal(result.claims.actorId, 'usr_env_admin');
      assert.equal(result.claims.tier, 'enterprise');
      assert.ok(result.claims.scopes.includes('dns:write:delete'));
    }
  });

  it('verifies authoritative key registered in-memory for testing', () => {
    registerAuthoritativeKeyForTesting('atk_live_test_acme_admin', {
      tenantId: 'tenant_customerAcme',
      actorId: 'usr_live_acme_admin',
      tier: 'enterprise',
      scopes: ['account:read', 'dns:write:delete']
    });

    const result = verifyAuthToken('atk_live_test_acme_admin');
    assert.equal(result.success, true);
    if (result.success) {
      assert.equal(result.claims.tenantId, 'tenant_customerAcme');
      assert.equal(result.claims.actorId, 'usr_live_acme_admin');
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

  it('verifies cryptographically signed valid JWT with HMAC-SHA256 signature and mandatory claims', () => {
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

  it('rejects JWT missing mandatory exp claim with 401 MISSING_EXP_CLAIM', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://api.aeitron.com',
      aud: 'aeitron-mcp',
      sub: 'usr_no_exp',
      scopes: ['account:read']
      // exp is omitted!
    })).toString('base64url');
    const secret = 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890';
    const sig = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
    const jwtWithoutExp = `${header}.${payload}.${sig}`;

    const result = verifyAuthToken(jwtWithoutExp, { jwtSecret: secret });
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'MISSING_EXP_CLAIM');
    }
  });

  it('rejects JWT missing or untrusted issuer with 401 INVALID_ISSUER', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://untrusted-attacker.com',
      aud: 'aeitron-mcp',
      exp: Math.floor(Date.now() / 1000) + 3600,
      scopes: ['account:read']
    })).toString('base64url');
    const secret = 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890';
    const sig = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
    const untrustedJwt = `${header}.${payload}.${sig}`;

    const result = verifyAuthToken(untrustedJwt, { jwtSecret: secret });
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'INVALID_ISSUER');
    }
  });

  it('rejects JWT missing or wrong audience with 401 INVALID_AUDIENCE', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://api.aeitron.com',
      aud: 'other-service-aud', // wrong audience!
      exp: Math.floor(Date.now() / 1000) + 3600,
      scopes: ['account:read']
    })).toString('base64url');
    const secret = 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890';
    const sig = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
    const wrongAudJwt = `${header}.${payload}.${sig}`;

    const result = verifyAuthToken(wrongAudJwt, { jwtSecret: secret });
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'INVALID_AUDIENCE');
    }
  });

  it('rejects JWT missing scopes claim with 401 MISSING_SCOPES_CLAIM and denies default privileges', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://api.aeitron.com',
      aud: 'aeitron-mcp',
      exp: Math.floor(Date.now() / 1000) + 3600
      // scopes omitted!
    })).toString('base64url');
    const secret = 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890';
    const sig = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
    const noScopesJwt = `${header}.${payload}.${sig}`;

    const result = verifyAuthToken(noScopesJwt, { jwtSecret: secret });
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'MISSING_SCOPES_CLAIM');
    }
  });

  it('rejects forged JWT signature with 401 INVALID_SIGNATURE', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://api.aeitron.com',
      aud: 'aeitron-mcp',
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
      tenant_id: 'tenant_expired',
      exp: 1000 // Year 1970
    });

    const result = verifyAuthToken(expiredJwt);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'TOKEN_EXPIRED');
    }
  });

  it('rejects JWT missing mandatory actor (sub) claim with 401 MISSING_ACTOR_CLAIM', () => {
    const noActorJwt = createSignedTestJwt({
      sub: '',
      actor_id: ''
    });

    const result = verifyAuthToken(noActorJwt);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'MISSING_ACTOR_CLAIM');
    }
  });

  it('rejects JWT missing mandatory tenant claim with 401 MISSING_TENANT_CLAIM', () => {
    const noTenantJwt = createSignedTestJwt({
      tenant_id: '',
      org_id: ''
    });

    const result = verifyAuthToken(noTenantJwt);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.status, 401);
      assert.equal(result.code, 'MISSING_TENANT_CLAIM');
    }
  });

  it('verifies cryptographically signed RS256 JWT using RSA public key', () => {
    const rsaJwt = createSignedTestJwt(
      {
        sub: 'usr_rsa_user_1',
        tenant_id: 'tenant_rsa_workspace',
        scopes: ['account:read', 'dns:read']
      },
      { algorithm: 'RS256' }
    );

    const result = verifyAuthToken(rsaJwt);
    assert.equal(result.success, true);
    if (result.success) {
      assert.equal(result.claims.actorId, 'usr_rsa_user_1');
      assert.equal(result.claims.tenantId, 'tenant_rsa_workspace');
      assert.ok(result.claims.scopes.includes('dns:read'));
    }
  });

  it('fails closed when checking authorization for an unmapped tool name', () => {
    const result = checkToolAuthorization('arbitrary_unknown_new_tool', {
      actorId: 'usr_admin',
      tenantId: 'tenant_admin',
      tier: 'enterprise',
      scopes: ['*'],
      livemode: true
    });

    assert.equal(result.authorized, false);
    assert.ok(result.error?.includes('Unmapped tool'));
  });

  it('issues and verifies cryptographic DNS deletion challenge tokens with single-use replay protection', () => {
    const challenge = issueDnsDeletionChallenge('tenant_acme', 'aeitron.com', 'rec_01');
    assert.ok(challenge.token.startsWith('del_tok_'));
    assert.ok(challenge.expiresAt > Date.now());

    // Valid verification and atomic consumption
    const verified = verifyDnsDeletionChallenge(challenge.token, 'tenant_acme', 'aeitron.com', 'rec_01');
    assert.equal(verified.valid, true);

    // Replay attempt must be strictly rejected
    const replayAttempt = verifyDnsDeletionChallenge(challenge.token, 'tenant_acme', 'aeitron.com', 'rec_01');
    assert.equal(replayAttempt.valid, false);
    assert.ok(replayAttempt.error?.includes('replay'));

    // Mismatched domain verification on a fresh token
    const freshChallenge1 = issueDnsDeletionChallenge('tenant_acme', 'aeitron.com', 'rec_01');
    const badDomain = verifyDnsDeletionChallenge(freshChallenge1.token, 'tenant_acme', 'other-domain.com', 'rec_01');
    assert.equal(badDomain.valid, false);
    assert.ok(badDomain.error?.includes('match'));

    // Mismatched recordId verification on a fresh token
    const freshChallenge2 = issueDnsDeletionChallenge('tenant_acme', 'aeitron.com', 'rec_01');
    const badRecord = verifyDnsDeletionChallenge(freshChallenge2.token, 'tenant_acme', 'aeitron.com', 'rec_wrong_99');
    assert.equal(badRecord.valid, false);

    // Forged signature verification
    const forgedToken = freshChallenge2.token.slice(0, -6) + 'abcdef';
    const badSig = verifyDnsDeletionChallenge(forgedToken, 'tenant_acme', 'aeitron.com', 'rec_01');
    assert.equal(badSig.valid, false);
  });

  it('generates compliant RFC 8414 OAuth 2.0 metadata', () => {
    const meta = getOAuthDiscoveryMetadata('https://api.aeitron.com');
    assert.equal(meta.issuer, 'https://api.aeitron.com');
    assert.equal(meta.token_endpoint, 'https://api.aeitron.com/v1/auth/token');
    assert.deepEqual(meta.grant_types_supported, ['client_credentials']);
  });

  it('returns compliant RFC 7517 JWKS metadata with valid RSA public key', () => {
    const jwks = getJwksMetadata();
    assert.ok(Array.isArray(jwks.keys));
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].kty, 'RSA');
    assert.equal(jwks.keys[0].alg, 'RS256');
    assert.ok(typeof (jwks.keys[0] as Record<string, unknown>).n === 'string');
    assert.ok(typeof (jwks.keys[0] as Record<string, unknown>).e === 'string');
  });
});
