import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage } from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  extractTokenFromRequest,
  verifyAuthToken,
  checkToolAuthorization,
  createSignedTestJwt,
  issueOAuthAccessToken,
  getOAuthDiscoveryMetadata,
  getJwksMetadata,
  registerAuthoritativeKeyForTesting,
  registerHistoricalRsaKeyForTesting,
  clearTestRegistries,
  loadAuthoritativeKeysFromEnv,
  issueDnsDeletionChallenge,
  verifyDnsDeletionChallenge,
  verifyRsaKeyPairMatch,
  createDnsDeletionRequest,
  getDnsDeletionRequest,
  getPendingDnsDeletionRequest,
  authorizeDnsDeletionRequest,
  createAuthorizedDnsDeletionToken,
  loadOrGenerateRsaKeyPair,
  listPendingDnsDeletionRequests,
  validateDnsStatePayload,
  markDnsDeletionCompleted,
  markDnsDeletionFailed,
  markDnsDeletionExecutionUnknown,
  reconcileDnsDeletionStatus,
  isStorageReady,
  isRsaReady,
  withDnsStateLock,
  toRedactedDnsRequestDto,
  hasRecentHumanMfa,
  checkDnsDeletionRateLimit,
  MAX_DNS_RATE_LIMIT_BUCKETS,
  _clearDnsDeletionRateLimits,
  ACTIVE_KID
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
    assert.ok(jwks.keys.length >= 1);
    assert.equal(jwks.keys[0].kty, 'RSA');
    assert.equal(jwks.keys[0].alg, 'RS256');
    assert.ok(typeof (jwks.keys[0] as Record<string, unknown>).n === 'string');
    assert.ok(typeof (jwks.keys[0] as Record<string, unknown>).e === 'string');
  });

  it('supports key rotation: exposes historical public keys in JWKS and verifies historical tokens', () => {
    // Generate a separate historical RSA key pair
    const oldPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const historicalKid = 'aeitron-mcp-rsa-historical-v0';
    registerHistoricalRsaKeyForTesting(historicalKid, oldPair.publicKey);

    // JWKS must now publish both keys
    const jwks = getJwksMetadata();
    const foundOldKey = jwks.keys.find((k) => k.kid === historicalKid);
    assert.ok(foundOldKey, 'Historical key must be exposed in JWKS during rotation grace period');

    // Create a token signed by the historical private key
    const headerB64 = Buffer.from(JSON.stringify({
      alg: 'RS256',
      typ: 'JWT',
      kid: historicalKid
    })).toString('base64url');

    const payloadB64 = Buffer.from(JSON.stringify({
      iss: 'https://api.aeitron.com',
      aud: 'aeitron-mcp',
      sub: 'usr_historical_client',
      tenant_id: 'tenant_legacy_org',
      scopes: ['account:read'],
      exp: Math.floor(Date.now() / 1000) + 1800
    })).toString('base64url');

    const content = `${headerB64}.${payloadB64}`;
    const sig = crypto.createSign('RSA-SHA256').update(content).sign(oldPair.privateKey, 'base64url');
    const historicalJwt = `${content}.${sig}`;

    // Token signed with historical key must verify successfully
    const authResult = verifyAuthToken(historicalJwt);
    assert.equal(authResult.success, true);
    if (authResult.success) {
      assert.equal(authResult.claims.actorId, 'usr_historical_client');
      assert.equal(authResult.claims.tenantId, 'tenant_legacy_org');
    }
  });

  it('issueOAuthAccessToken: creates RFC 7519 RS256 token matching JWKS active kid', () => {
    const token = issueOAuthAccessToken({
      clientId: 'client_sample_123',
      clientSecretHash: '',
      tenantId: 'tenant_cloud_01',
      actorId: 'usr_cloud_admin',
      scopes: ['account:read', 'dns:write']
    });

    const [hB64, pB64] = token.split('.');
    const header = JSON.parse(Buffer.from(hB64, 'base64url').toString('utf-8')) as { alg: string; kid: string };
    assert.equal(header.alg, 'RS256');
    assert.equal(header.kid, ACTIVE_KID);

    // Verify token validity
    const verified = verifyAuthToken(token);
    assert.equal(verified.success, true);
  });

  it('verifyRsaKeyPairMatch: accurately validates correspondence between private and public keys', () => {
    const pair1 = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const pair2 = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    assert.equal(verifyRsaKeyPairMatch(pair1.privateKey, pair1.publicKey), true);
    assert.equal(verifyRsaKeyPairMatch(pair2.privateKey, pair2.publicKey), true);
    assert.equal(verifyRsaKeyPairMatch(pair1.privateKey, pair2.publicKey), false);
    assert.equal(verifyRsaKeyPairMatch(pair2.privateKey, pair1.publicKey), false);
    assert.equal(verifyRsaKeyPairMatch('invalid_key', pair1.publicKey), false);
  });

  it('DNS deletion approval hardening: strictly rejects challenge tokens missing mandatory requestId', () => {
    // Generate forged token payload lacking requestId
    const payload = JSON.stringify({
      action: 'dns_delete_challenge',
      tenantId: 'tenant_acme',
      domain: 'aeitron.com',
      recordId: 'rec_01',
      nonce: '12345678',
      expiresAt: Date.now() + 60000
    });
    const payloadB64 = Buffer.from(payload).toString('base64url');
    const sig = crypto.createHmac('sha256', 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890')
      .update(`del:${payloadB64}`)
      .digest('base64url');
    const tokenWithoutRequestId = `del_tok_${payloadB64}.${sig}`;

    const res = verifyDnsDeletionChallenge(tokenWithoutRequestId, 'tenant_acme', 'aeitron.com', 'rec_01');
    assert.equal(res.valid, false);
    assert.ok(res.error?.includes('requestId'));
  });

  it('DNS deletion approval hardening: strictly rejects challenge tokens referencing nonexistent request', () => {
    const payload = JSON.stringify({
      action: 'dns_delete_challenge',
      requestId: 'del_req_nonexistent_fake_id_1234',
      tenantId: 'tenant_acme',
      domain: 'aeitron.com',
      recordId: 'rec_01',
      nonce: '12345678',
      expiresAt: Date.now() + 60000
    });
    const payloadB64 = Buffer.from(payload).toString('base64url');
    const sig = crypto.createHmac('sha256', 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890')
      .update(`del:${payloadB64}`)
      .digest('base64url');
    const token = `del_tok_${payloadB64}.${sig}`;

    const res = verifyDnsDeletionChallenge(token, 'tenant_acme', 'aeitron.com', 'rec_01');
    assert.equal(res.valid, false);
    assert.ok(res.error?.includes('not found'));
  });

  it('DNS deletion approval hardening: strictly rejects challenge tokens referencing unauthorized request', () => {
    // 1. Create a request but DO NOT authorize it
    const req = createDnsDeletionRequest('tenant_acme', 'usr_requester', 'aeitron.com', 'rec_unauthorized_99');

    // Craft token with this requestId before operator authorization
    const payload = JSON.stringify({
      action: 'dns_delete_challenge',
      requestId: req.requestId,
      tenantId: 'tenant_acme',
      domain: 'aeitron.com',
      recordId: 'rec_unauthorized_99',
      nonce: '12345678',
      expiresAt: Date.now() + 60000
    });
    const payloadB64 = Buffer.from(payload).toString('base64url');
    const sig = crypto.createHmac('sha256', 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890')
      .update(`del:${payloadB64}`)
      .digest('base64url');
    const token = `del_tok_${payloadB64}.${sig}`;

    const res = verifyDnsDeletionChallenge(token, 'tenant_acme', 'aeitron.com', 'rec_unauthorized_99');
    assert.equal(res.valid, false);
    assert.ok(res.error?.includes('not been authorized'));
  });

  it('DNS deletion approval hardening: strictly rejects challenge tokens with mismatched approvalToken', () => {
    const req = createDnsDeletionRequest('tenant_acme', 'usr_requester', 'aeitron.com', 'rec_mismatch_88');
    const authRes = authorizeDnsDeletionRequest({
      actorId: 'usr_operator',
      tenantId: 'tenant_acme',
      tier: 'enterprise',
      scopes: ['dns:delete:approve'],
      livemode: false,
      actorType: 'human',
      authMethods: ['mfa'],
      authTime: Math.floor(Date.now() / 1000)
    }, req.requestId);
    assert.equal(authRes.success, true);

    // Craft a DIFFERENT validly-signed token referencing the same requestId
    const payload = JSON.stringify({
      action: 'dns_delete_challenge',
      requestId: req.requestId,
      tenantId: 'tenant_acme',
      domain: 'aeitron.com',
      recordId: 'rec_mismatch_88',
      nonce: 'different_nonce_888',
      expiresAt: Date.now() + 60000
    });
    const payloadB64 = Buffer.from(payload).toString('base64url');
    const sig = crypto.createHmac('sha256', 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890')
      .update(`del:${payloadB64}`)
      .digest('base64url');
    const differentToken = `del_tok_${payloadB64}.${sig}`;

    const res = verifyDnsDeletionChallenge(differentToken, 'tenant_acme', 'aeitron.com', 'rec_mismatch_88');
    assert.equal(res.valid, false);
    assert.ok(res.error?.includes('does not match authorized token'));
  });

  it('DNS deletion approval hardening: strictly rejects creator self-approval', () => {
    const req = createDnsDeletionRequest('tenant_acme', 'usr_creator_42', 'aeitron.com', 'rec_self_appr');
    const authRes = authorizeDnsDeletionRequest({
      actorId: 'usr_creator_42', // Same actor as requester
      tenantId: 'tenant_acme',
      tier: 'enterprise',
      scopes: ['dns:delete:approve'],
      livemode: false,
      actorType: 'human',
      authMethods: ['mfa'],
      authTime: Math.floor(Date.now() / 1000)
    }, req.requestId);
    assert.equal(authRes.success, false);
    assert.equal(authRes.status, 403);
    assert.ok(authRes.error.includes('cannot approve their own DNS deletion requests'));
  });

  it('DNS deletion approval hardening: strictly rejects approval if operator lacks dns:delete:approve scope', () => {
    const req = createDnsDeletionRequest('tenant_acme', 'usr_requester', 'aeitron.com', 'rec_scope_test');
    const authRes =  authorizeDnsDeletionRequest({
      actorId: 'usr_operator_diff',
      tenantId: 'tenant_acme',
      tier: 'enterprise',
      scopes: ['dns:write:delete'], // Only dns:write:delete, missing dns:delete:approve
      livemode: false,
      actorType: 'human',
      authMethods: ['mfa'],
      authTime: Math.floor(Date.now() / 1000)
    }, req.requestId);
    assert.equal(authRes.success, false);
    assert.equal(authRes.status, 403);
    assert.ok(authRes.error.includes('dns:delete:approve'));
  });

  it('DNS deletion approval hardening: strictly rejects approval across different tenants', () => {
    const req = createDnsDeletionRequest('tenant_acme', 'usr_requester', 'aeitron.com', 'rec_cross_tenant');
    const authRes = authorizeDnsDeletionRequest({
      actorId: 'usr_operator_other',
      tenantId: 'tenant_evil_corp',
      tier: 'enterprise',
      scopes: ['dns:delete:approve'],
      livemode: false,
      actorType: 'human',
      authMethods: ['mfa'],
      authTime: Math.floor(Date.now() / 1000)
    }, req.requestId);
    assert.equal(authRes.success, false);
    assert.equal(authRes.status, 403);
    assert.ok(authRes.error.includes('tenant does not match'));
  });

  it('issueDnsDeletionChallenge: strictly prohibited in hardened environments', () => {
    const prevEnv = process.env.AEITRON_ENV;
    try {
      process.env.AEITRON_ENV = 'production';
      assert.throws(() => {
        issueDnsDeletionChallenge('tenant_acme', 'aeitron.com', 'rec_prod_1');
      }, /SECURITY VIOLATION.*hardened/);
    } finally {
      if (prevEnv !== undefined) process.env.AEITRON_ENV = prevEnv;
      else delete process.env.AEITRON_ENV;
    }
  });

  it('loadOrGenerateRsaKeyPair: strictly throws when configured RSA key file does not exist in hardened environment', () => {
    const prevEnv = process.env.AEITRON_ENV;
    const prevKeyFile = process.env.AEITRON_RSA_KEY_FILE;
    try {
      process.env.AEITRON_ENV = 'production';
      process.env.AEITRON_RSA_KEY_FILE = 'C:\\nonexistent\\path\\to\\rsa_private.json';
      assert.throws(() => {
        loadOrGenerateRsaKeyPair();
      }, /CRITICAL.*does not exist/);
    } finally {
      if (prevEnv !== undefined) process.env.AEITRON_ENV = prevEnv;
      else delete process.env.AEITRON_ENV;
      if (prevKeyFile !== undefined) {
        process.env.AEITRON_RSA_KEY_FILE = prevKeyFile;
      } else {
        delete process.env.AEITRON_RSA_KEY_FILE;
      }
    }
  });

  it('loadOrGenerateRsaKeyPair: strictly throws when RSA public key is configured without private key in hardened environment', () => {
    const prevEnv = process.env.AEITRON_ENV;
    const prevPub = process.env.AEITRON_RSA_PUBLIC_KEY;
    const prevPriv = process.env.AEITRON_RSA_PRIVATE_KEY;
    try {
      process.env.AEITRON_ENV = 'production';
      delete process.env.AEITRON_RSA_PRIVATE_KEY;
      delete process.env.AEITRON_JWT_PRIVATE_KEY;
      process.env.AEITRON_RSA_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0\n-----END PUBLIC KEY-----';
      assert.throws(() => {
        loadOrGenerateRsaKeyPair();
      }, /CRITICAL CONFIGURATION ERROR: RSA public key is configured without a corresponding private signing key/);
    } finally {
      if (prevEnv !== undefined) process.env.AEITRON_ENV = prevEnv;
      else delete process.env.AEITRON_ENV;
      if (prevPub !== undefined) process.env.AEITRON_RSA_PUBLIC_KEY = prevPub;
      else delete process.env.AEITRON_RSA_PUBLIC_KEY;
      if (prevPriv !== undefined) process.env.AEITRON_RSA_PRIVATE_KEY = prevPriv;
      else delete process.env.AEITRON_RSA_PRIVATE_KEY;
    }
  });

  it('tenantId === "anonymous" strictly rejected on operator deletion approval', () => {
    const req = createDnsDeletionRequest('tenant_customer_123', 'usr_creator', 'example.com', 'rec_123');
    const authRes = authorizeDnsDeletionRequest(
      {
        actorId: 'usr_operator_anon',
        tenantId: 'anonymous',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: Math.floor(Date.now() / 1000)
      },
      req.requestId
    );

    assert.equal(authRes.success, false);
    if (!authRes.success) {
      assert.equal(authRes.status, 403);
      assert.ok(authRes.error.includes('tenant does not match'));
    }
  });

  it('listPendingDnsDeletionRequests: returns empty array when tenantId is anonymous or missing', () => {
    createDnsDeletionRequest('tenant_customer_456', 'usr_creator_2', 'example.com', 'rec_456');
    assert.deepEqual(listPendingDnsDeletionRequests('anonymous'), []);
    assert.deepEqual(listPendingDnsDeletionRequests(undefined), []);
    const matching = listPendingDnsDeletionRequests('tenant_customer_456');
    assert.ok(matching.length >= 1);
  });

  it('validateDnsStatePayload: strictly validates schema and rejects malformed state data', () => {
    // 1. Root non-object
    assert.throws(() => validateDnsStatePayload('invalid'), /root must be an object/);

    // 2. Unsupported version
    assert.throws(() => validateDnsStatePayload({ version: 2, requests: [], consumedTokenHashes: [] }), /unsupported version/);

    // 3. Invalid requests array
    assert.throws(() => validateDnsStatePayload({ version: 1, requests: 'not_an_array', consumedTokenHashes: [] }), /requests must be an array/);

    // 4. Invalid consumedTokenHashes
    assert.throws(() => validateDnsStatePayload({ version: 1, requests: [], consumedTokenHashes: ['short_hash'] }), /64-char SHA-256 hex string/);

    // 5. Valid payload
    const valid = validateDnsStatePayload({
      version: 1,
      requests: [
        {
          requestId: 'del_req_1',
          tenantId: 'tenant_1',
          actorId: 'usr_1',
          domain: 'aeitron.com',
          recordId: 'rec_1',
          createdAt: Date.now(),
          expiresAt: Date.now() + 10000,
          authorized: false
        }
      ],
      consumedTokenHashes: [crypto.createHash('sha256').update('test_tok').digest('hex')]
    });
    assert.equal(valid.version, 1);
    assert.equal(valid.requests.length, 1);
    assert.equal(valid.requests[0].status, 'pending');
  });

  it('DNS deletion state machine: transitions from pending -> approved -> executing -> completed', () => {
    const req = createDnsDeletionRequest('tenant_state_test', 'usr_client', 'example.com', 'rec_state_1');
    assert.ok(req.requestId);

    // 1. Operator authorizes
    const authRes = authorizeDnsDeletionRequest(
      {
        actorId: 'usr_operator_state',
        tenantId: 'tenant_state_test',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: Math.floor(Date.now() / 1000)
      },
      req.requestId
    );
    assert.equal(authRes.success, true);
    if (!authRes.success) return;

    // 2. Consume approval token -> transitions to 'executing'
    const consumeRes = verifyDnsDeletionChallenge(
      authRes.token,
      'tenant_state_test',
      'example.com',
      'rec_state_1'
    );
    assert.equal(consumeRes.valid, true);
    if (consumeRes.valid) {
      assert.equal(consumeRes.requestId, req.requestId);
    }

    // 3. Mark completed after upstream DNS call
    markDnsDeletionCompleted(req.requestId);

    // 4. Verify replay is blocked
    const replayRes = verifyDnsDeletionChallenge(
      authRes.token,
      'tenant_state_test',
      'example.com',
      'rec_state_1'
    );
    assert.equal(replayRes.valid, false);
    if (!replayRes.valid) {
      assert.ok(replayRes.error.includes('already been consumed'));
    }
  });

  it('withDnsStateLock: acquires and releases cross-process lockfile safely', () => {
    let executed = false;
    const result = withDnsStateLock(() => {
      executed = true;
      return 'lock_success';
    });
    assert.equal(executed, true);
    assert.equal(result, 'lock_success');
  });

  it('markDnsDeletionExecutionUnknown and reconcileDnsDeletionStatus handle upstream timeout safely', () => {
    const req = createDnsDeletionRequest('tenant_timeout_test', 'usr_client', 'example.com', 'rec_timeout_1');
    assert.ok(req.requestId);

    // Operator authorizes
    const authRes = authorizeDnsDeletionRequest(
      {
        actorId: 'usr_operator_timeout',
        tenantId: 'tenant_timeout_test',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: Math.floor(Date.now() / 1000)
      },
      req.requestId
    );
    assert.equal(authRes.success, true);
    if (!authRes.success) return;

    // Execution starts (consumed challenge)
    verifyDnsDeletionChallenge(authRes.token, 'tenant_timeout_test', 'example.com', 'rec_timeout_1');

    // Upstream times out: transition to execution_unknown
    markDnsDeletionExecutionUnknown(req.requestId, 'Gateway timeout after 5000ms');

    // Reconcile when record has already been removed by upstream edge
    const reconcileSuccess = reconcileDnsDeletionStatus(req.requestId, false);
    assert.equal(reconcileSuccess.success, true);
    assert.equal(reconcileSuccess.status, 'completed');

    // Reconcile a failed timeout (record still present: safe interim state keeps execution_unknown)
    const req2 = createDnsDeletionRequest('tenant_timeout_test', 'usr_client', 'example.com', 'rec_timeout_2');
    markDnsDeletionExecutionUnknown(req2.requestId, 'Connection reset by peer');
    const reconcileFailed = reconcileDnsDeletionStatus(req2.requestId, true);
    assert.equal(reconcileFailed.success, true);
    assert.equal(reconcileFailed.status, 'execution_unknown');
  });

  it('createDnsDeletionRequest strictly rejects anonymous or empty tenant and actor', () => {
    // 1. anonymous tenant
    assert.throws(
      () => createDnsDeletionRequest('anonymous', 'usr_1', 'example.com', 'rec_1'),
      /without a valid tenant and actor/
    );

    // 2. empty tenant
    assert.throws(
      () => createDnsDeletionRequest('', 'usr_1', 'example.com', 'rec_1'),
      /without a valid tenant and actor/
    );

    // 3. empty actor
    assert.throws(
      () => createDnsDeletionRequest('tenant_valid', '', 'example.com', 'rec_1'),
      /without a valid tenant and actor/
    );

    // 4. empty domain or recordId
    assert.throws(
      () => createDnsDeletionRequest('tenant_valid', 'usr_valid', '', 'rec_1'),
      /without a valid domain and recordId/
    );
  });

  it('getDnsDeletionRequest retains terminal requests (completed, failed) across state reloads', () => {
    const req = createDnsDeletionRequest('tenant_history_test', 'usr_client_1', 'example.com', 'rec_history_1');
    assert.ok(req.requestId);

    // Authorize & complete
    const authRes = authorizeDnsDeletionRequest(
      {
        actorId: 'usr_operator_hist',
        tenantId: 'tenant_history_test',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: Math.floor(Date.now() / 1000)
      },
      req.requestId
    );
    assert.equal(authRes.success, true);
    if (!authRes.success) return;

    verifyDnsDeletionChallenge(authRes.token, 'tenant_history_test', 'example.com', 'rec_history_1');
    markDnsDeletionCompleted(req.requestId);

    // 1. getDnsDeletionRequest returns completed record
    const loadedReq = getDnsDeletionRequest(req.requestId);
    assert.ok(loadedReq);
    assert.equal(loadedReq.status, 'completed');

    // 2. getPendingDnsDeletionRequest strictly returns undefined for non-pending requests
    const pendingReq = getPendingDnsDeletionRequest(req.requestId);
    assert.equal(pendingReq, undefined);
  });

  it('validateDnsStatePayload: rejects invalid timestamps, non-boolean authorized, and invalid statuses', () => {
    const baseRequest = {
      requestId: 'del_req_valid',
      tenantId: 'tenant_1',
      actorId: 'usr_1',
      domain: 'aeitron.com',
      recordId: 'rec_1',
      createdAt: 1000,
      expiresAt: 2000,
      authorized: false
    };

    // Non-integer timestamp
    assert.throws(
      () => validateDnsStatePayload({ version: 1, requests: [{ ...baseRequest, createdAt: '1000' }], consumedTokenHashes: [] }),
      /createdAt in request del_req_valid must be a positive safe integer timestamp/
    );

    // expiresAt <= createdAt
    assert.throws(
      () => validateDnsStatePayload({ version: 1, requests: [{ ...baseRequest, expiresAt: 900 }], consumedTokenHashes: [] }),
      /expiresAt must be greater than createdAt/
    );

    // Non-strict boolean authorized
    assert.throws(
      () => validateDnsStatePayload({ version: 1, requests: [{ ...baseRequest, authorized: 'true' }], consumedTokenHashes: [] }),
      /authorized must be a strict boolean/
    );

    // Invalid status string
    assert.throws(
      () => validateDnsStatePayload({ version: 1, requests: [{ ...baseRequest, status: 'nuked' }], consumedTokenHashes: [] }),
      /status 'nuked' is not allowed/
    );
  });

  it('isStorageReady and isRsaReady verify server operational readiness', () => {
    assert.equal(typeof isStorageReady(), 'boolean');
    assert.equal(typeof isRsaReady(), 'boolean');
    assert.equal(isStorageReady(), true);
    assert.equal(isRsaReady(), true);
  });

  it('getDnsDeletionRequest retains unresolved in-flight executing requests across state reloads even after expiresAt has passed', () => {
    const req = createDnsDeletionRequest('tenant_inflight_test', 'usr_client_2', 'example.com', 'rec_inflight_1');
    assert.ok(req.requestId);

    const authRes = authorizeDnsDeletionRequest(
      {
        actorId: 'usr_operator_inflight',
        tenantId: 'tenant_inflight_test',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: Math.floor(Date.now() / 1000)
      },
      req.requestId
    );
    assert.equal(authRes.success, true);
    if (!authRes.success) return;

    // Move to executing state
    const consumeRes = verifyDnsDeletionChallenge(authRes.token, 'tenant_inflight_test', 'example.com', 'rec_inflight_1');
    assert.equal(consumeRes.valid, true);

    // Read and simulate past expiresAt (as if approval window expired during long-running operation)
    const inFlightReq = getDnsDeletionRequest(req.requestId)!;
    assert.equal(inFlightReq.status, 'executing');

    // Manually write state with past expiresAt (createdAt < expiresAt < now) to test recovery logic on disk load
    const stateFile = path.join(process.cwd(), '.aeitron-state', 'dns-deletion-state.json');
    const state = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
    const targetItem = state.requests.find((r: any) => r.requestId === req.requestId);
    targetItem.createdAt = Date.now() - 600000; // Created 10 minutes ago
    targetItem.expiresAt = Date.now() - 60000;  // Expired 1 minute ago
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2));

    // Reload state - must retain unresolved in-flight executing request
    const reloaded = getDnsDeletionRequest(req.requestId);
    assert.ok(reloaded, 'Executing request must be retained for recovery even if expiresAt has passed');
    assert.equal(reloaded.status, 'executing');
  });

  it('authorizeDnsDeletionRequest strictly rejects service / machine account tokens', () => {
    const req = createDnsDeletionRequest('tenant_svc_guard', 'usr_client_3', 'example.com', 'rec_svc_guard_1');
    const authRes = authorizeDnsDeletionRequest(
      {
        actorId: 'svc_background_bot',
        tenantId: 'tenant_svc_guard',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'service'
      },
      req.requestId
    );
    assert.equal(authRes.success, false);
    assert.equal(authRes.status, 403);
    assert.ok(authRes.error.includes('human operator with recent MFA verification'));
  });

  it('checkDnsDeletionRateLimit bounds requests per tenant and clearTestRegistries resets limits', async () => {
    const { checkDnsDeletionRateLimit, clearTestRegistries } = await import('../src/auth.js');
    clearTestRegistries();

    const tenant = 'tenant_burst_test';
    // Consume limit of 30
    for (let i = 0; i < 30; i++) {
      assert.equal(checkDnsDeletionRateLimit(tenant), true);
    }
    // 31st request is throttled
    assert.equal(checkDnsDeletionRateLimit(tenant), false);

    // Reset clears buckets
    clearTestRegistries();
    assert.equal(checkDnsDeletionRateLimit(tenant), true);
  });

  it('consumedTokens TTL pruning: automatically prunes hashes where retainUntil <= now', () => {
    const stateFile = path.join(process.cwd(), '.aeitron-state', 'dns-deletion-state.json');
    const expiredHash = crypto.createHash('sha256').update('expired-token-1').digest('hex');
    const validHash = crypto.createHash('sha256').update('valid-token-2').digest('hex');

    const state = {
      version: 1,
      requests: [],
      consumedTokens: [
        { hash: expiredHash, retainUntil: Date.now() - 5000 },
        { hash: validHash, retainUntil: Date.now() + 60000 }
      ],
      consumedTokenHashes: [expiredHash, validHash]
    };
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2));

    // Create a new request to trigger state load and save
    createDnsDeletionRequest('tenant_prune_test', 'usr_prune', 'aeitron.com', 'rec_prune_1');

    const reloaded = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
    const tokenHashes = reloaded.consumedTokens.map((t: any) => t.hash);
    assert.equal(tokenHashes.includes(validHash), true, 'Valid token must be retained');
    assert.equal(tokenHashes.includes(expiredHash), false, 'Expired token hash must be pruned');
  });

  describe('Unified Human MFA & Security Hardening Suite', () => {
    it('hasRecentHumanMfa strictly validates human actor, MFA method, and safe recent timestamp', () => {
      const now = Math.floor(Date.now() / 1000);

      // Valid case: human + MFA + within 5 min
      assert.equal(hasRecentHumanMfa({
        actorId: 'usr_h1',
        tenantId: 'tenant_1',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: now - 120
      }, now), true);

      // Exactly at 300s boundary: allowed
      assert.equal(hasRecentHumanMfa({
        actorId: 'usr_h1',
        tenantId: 'tenant_1',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['password', 'mfa'],
        authTime: now - 300
      }, now), true);

      // Rejection: actorType === 'service'
      assert.equal(hasRecentHumanMfa({
        actorId: 'svc_1',
        tenantId: 'tenant_1',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'service',
        authMethods: ['mfa'],
        authTime: now
      }, now), false);

      // Rejection: missing actorType
      assert.equal(hasRecentHumanMfa({
        actorId: 'usr_h1',
        tenantId: 'tenant_1',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        authMethods: ['mfa'],
        authTime: now
      }, now), false);

      // Rejection: human without MFA
      assert.equal(hasRecentHumanMfa({
        actorId: 'usr_h1',
        tenantId: 'tenant_1',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['password'],
        authTime: now
      }, now), false);

      // Rejection: authTime > 300 seconds ago (expired session)
      assert.equal(hasRecentHumanMfa({
        actorId: 'usr_h1',
        tenantId: 'tenant_1',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: now - 301
      }, now), false);

      // Rejection: authTime in future
      assert.equal(hasRecentHumanMfa({
        actorId: 'usr_h1',
        tenantId: 'tenant_1',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: now + 60
      }, now), false);

      // Rejection: non-safe integer or undefined authTime
      assert.equal(hasRecentHumanMfa({
        actorId: 'usr_h1',
        tenantId: 'tenant_1',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa']
      }, now), false);
    });

    it('authorizeDnsDeletionRequest strictly enforces human MFA requirements across all paths', () => {
      const now = Math.floor(Date.now() / 1000);
      const req = createDnsDeletionRequest('tenant_mfa_test', 'usr_creator_mfa', 'example.com', 'rec_mfa_1');

      // 1. Rejected if actorType missing
      const resNoActor = authorizeDnsDeletionRequest({
        actorId: 'usr_op_1',
        tenantId: 'tenant_mfa_test',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        authMethods: ['mfa'],
        authTime: now
      }, req.requestId);
      assert.equal(resNoActor.success, false);
      assert.equal(resNoActor.status, 403);
      assert.ok(resNoActor.error.includes('human operator with recent MFA'));

      // 2. Rejected if human lacks MFA method
      const resNoMfa = authorizeDnsDeletionRequest({
        actorId: 'usr_op_2',
        tenantId: 'tenant_mfa_test',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['password'],
        authTime: now
      }, req.requestId);
      assert.equal(resNoMfa.success, false);
      assert.equal(resNoMfa.status, 403);

      // 3. Rejected if authTime > 300s old
      const resOldAuth = authorizeDnsDeletionRequest({
        actorId: 'usr_op_3',
        tenantId: 'tenant_mfa_test',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: now - 305
      }, req.requestId);
      assert.equal(resOldAuth.success, false);
      assert.equal(resOldAuth.status, 403);

      // 4. Allowed when human + MFA + recent authTime
      const resValid = authorizeDnsDeletionRequest({
        actorId: 'usr_op_4',
        tenantId: 'tenant_mfa_test',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: false,
        actorType: 'human',
        authMethods: ['mfa'],
        authTime: now - 30
      }, req.requestId);
      assert.equal(resValid.success, true);
    });

    it('acquireDnsStateLock fail-closed: throws STALE_DNS_STATE_LOCK when lock is held by dead process', () => {
      const lockPath = path.join(process.cwd(), '.aeitron-state', 'dns-deletion-state.lock');
      // Write lockfile referencing a dead PID (e.g. 9999999)
      fs.writeFileSync(lockPath, JSON.stringify({
        ownerToken: 'dead-owner-uuid',
        pid: 9999999,
        createdAt: Date.now() - 30000
      }));

      try {
        assert.throws(() => {
          withDnsStateLock(() => 'never_reached');
        }, /STALE_DNS_STATE_LOCK/);
      } finally {
        // Clean up test lock
        try { fs.unlinkSync(lockPath); } catch {}
      }
    });

    it('loadOrGenerateRsaKeyPair: strictly throws in hardened environment when neither AEITRON_RSA_PRIVATE_KEY nor AEITRON_RSA_KEY_FILE is configured', () => {
      const prevEnv = process.env.AEITRON_ENV;
      const prevKeyFile = process.env.AEITRON_RSA_KEY_FILE;
      const prevJwtKeyFile = process.env.AEITRON_JWT_KEY_FILE;
      const prevPriv = process.env.AEITRON_RSA_PRIVATE_KEY;
      const prevJwtPriv = process.env.AEITRON_JWT_PRIVATE_KEY;
      const prevPub = process.env.AEITRON_RSA_PUBLIC_KEY;
      const prevJwtPub = process.env.AEITRON_JWT_PUBLIC_KEY;
      try {
        process.env.AEITRON_ENV = 'production';
        delete process.env.AEITRON_RSA_KEY_FILE;
        delete process.env.AEITRON_JWT_KEY_FILE;
        delete process.env.AEITRON_RSA_PRIVATE_KEY;
        delete process.env.AEITRON_JWT_PRIVATE_KEY;
        delete process.env.AEITRON_RSA_PUBLIC_KEY;
        delete process.env.AEITRON_JWT_PUBLIC_KEY;

        assert.throws(() => {
          loadOrGenerateRsaKeyPair();
        }, /CRITICAL CONFIGURATION ERROR: AEITRON_RSA_PRIVATE_KEY or AEITRON_RSA_KEY_FILE must be configured in hardened environments/);
      } finally {
        if (prevEnv !== undefined) process.env.AEITRON_ENV = prevEnv;
        else delete process.env.AEITRON_ENV;
        if (prevKeyFile !== undefined) process.env.AEITRON_RSA_KEY_FILE = prevKeyFile;
        if (prevJwtKeyFile !== undefined) process.env.AEITRON_JWT_KEY_FILE = prevJwtKeyFile;
        if (prevPriv !== undefined) process.env.AEITRON_RSA_PRIVATE_KEY = prevPriv;
        if (prevJwtPriv !== undefined) process.env.AEITRON_JWT_PRIVATE_KEY = prevJwtPriv;
        if (prevPub !== undefined) process.env.AEITRON_RSA_PUBLIC_KEY = prevPub;
        if (prevJwtPub !== undefined) process.env.AEITRON_JWT_PUBLIC_KEY = prevJwtPub;
      }
    });

    it('checkDnsDeletionRateLimit: fails closed when active buckets reach MAX_DNS_RATE_LIMIT_BUCKETS', () => {
      _clearDnsDeletionRateLimits();
      try {
        for (let i = 0; i < MAX_DNS_RATE_LIMIT_BUCKETS; i++) {
          const allowed = checkDnsDeletionRateLimit(`tenant_cap_${i}`);
          assert.equal(allowed, true);
        }
        // Next distinct tenant bucket must fail closed to protect memory
        const overflow = checkDnsDeletionRateLimit('tenant_overflow_blocked');
        assert.equal(overflow, false, 'Rate limiter must fail closed when capacity cap is reached');
      } finally {
        _clearDnsDeletionRateLimits();
      }
    });
  });
});
