/**
 * Aeitron MCP Server — Cryptographic Authentication & Authorization Engine
 * Enforces fail-closed token validation, HMAC-SHA256 signature verification,
 * dynamic authoritative API key checking, mandatory JWT claims, and tool-level RBAC scopes.
 */

import { IncomingMessage } from 'node:http';
import crypto from 'node:crypto';
import { getConfig } from './config.js';

export interface AuthClaims {
  actorId: string;
  tenantId: string;
  tier: 'free' | 'developer' | 'enterprise' | 'sandbox';
  scopes: string[];
  livemode: boolean;
  expiresAt?: number;
}

export interface AuthSuccess {
  success: true;
  token: string;
  claims: AuthClaims;
}

export interface AuthFailure {
  success: false;
  status: 401 | 403;
  error: string;
  code: string;
}

export type AuthResult = AuthSuccess | AuthFailure;

/**
 * Strict tool-to-scope mapping required by the Aeitron security specification
 */
export const TOOL_SCOPES: Record<string, string> = {
  get_account: 'account:read',
  list_projects: 'projects:read',
  get_project: 'projects:read',
  get_dns_records: 'dns:read',
  get_usage: 'usage:read',
  create_project: 'projects:write',
  create_dns_record: 'dns:write',
  delete_dns_record: 'dns:write:delete'
};

export interface RegisteredKey {
  tenantId: string;
  actorId: string;
  tier: 'developer' | 'enterprise';
  scopes: string[];
}

export interface OAuthClient {
  clientId: string;
  clientSecretHash: string; // SHA-256 hash of secret
  tenantId: string;
  actorId: string;
  scopes: string[];
}

/**
 * Registry of authoritative live API keys.
 * Zero hardcoded keys in production. Keys are loaded dynamically from environment or hashed store.
 */
const AUTHORITATIVE_KEYS = new Map<string, RegisteredKey>();
const OAUTH_CLIENTS = new Map<string, OAuthClient>();

/**
 * Dynamically loads authoritative API keys from the AEITRON_API_KEYS environment variable.
 * Syntax: comma-separated "key:tenantId:actorId:scopes"
 * Example: "atk_live_key1:tenant_1:usr_1:account:read+dns:read,atk_live_key2:tenant_2:usr_2:*"
 */
export function loadAuthoritativeKeysFromEnv(rawKeys?: string): void {
  const envKeys = rawKeys || process.env.AEITRON_API_KEYS;
  if (!envKeys) return;

  const entries = envKeys.split(',').map((s) => s.trim()).filter(Boolean);
  for (const entry of entries) {
    const parts = entry.split(':');
    if (parts.length >= 4) {
      const key = parts[0];
      const tenantId = parts[1];
      const actorId = parts[2];
      let tier: 'developer' | 'enterprise' = 'developer';
      let scopesPart = parts.slice(3).join(':');

      if (parts[3] === 'enterprise' || parts[3] === 'developer') {
        tier = parts[3];
        scopesPart = parts.slice(4).join(':');
      }

      const scopes = scopesPart.split('+').map((s) => s.trim()).filter(Boolean);
      const hash = crypto.createHash('sha256').update(key).digest('hex');
      AUTHORITATIVE_KEYS.set(hash, { tenantId, actorId, tier, scopes });
    }
  }
}

/**
 * Dynamically loads registered OAuth clients from the AEITRON_OAUTH_CLIENTS environment variable.
 * Syntax: comma-separated "clientId:clientSecret:tenantId:actorId:scopes"
 */
export function loadOAuthClientsFromEnv(rawClients?: string): void {
  const envClients = rawClients || process.env.AEITRON_OAUTH_CLIENTS;
  if (!envClients) return;

  const entries = envClients.split(',').map((s) => s.trim()).filter(Boolean);
  for (const entry of entries) {
    const parts = entry.split(':');
    if (parts.length >= 5) {
      const clientId = parts[0];
      const secret = parts[1];
      const tenantId = parts[2];
      const actorId = parts[3];
      const scopes = parts[4].split('+').map((s) => s.trim()).filter(Boolean);

      const secretHash = crypto.createHash('sha256').update(secret).digest('hex');
      OAUTH_CLIENTS.set(clientId, {
        clientId,
        clientSecretHash: secretHash,
        tenantId,
        actorId,
        scopes
      });
    }
  }
}

// Load any environment keys/clients on initialization
loadAuthoritativeKeysFromEnv();
loadOAuthClientsFromEnv();

/**
 * Exclusively for test suites to register test credentials in-memory.
 * Disallowed in production if environment is 'production'.
 */
export function registerAuthoritativeKeyForTesting(key: string, meta: RegisteredKey): void {
  const config = getConfig();
  if (config.environment === 'production') {
    throw new Error('SECURITY VIOLATION: registerAuthoritativeKeyForTesting cannot be called in production.');
  }
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  AUTHORITATIVE_KEYS.set(hash, meta);
}

/**
 * Exclusively for test suites to register test OAuth clients.
 */
export function registerOAuthClientForTesting(client: OAuthClient): void {
  const config = getConfig();
  if (config.environment === 'production') {
    throw new Error('SECURITY VIOLATION: registerOAuthClientForTesting cannot be called in production.');
  }
  OAUTH_CLIENTS.set(client.clientId, client);
}

/**
 * Clear test registries between test executions
 */
export function clearTestRegistries(): void {
  AUTHORITATIVE_KEYS.clear();
  OAUTH_CLIENTS.clear();
}

/**
 * Authenticates an OAuth 2.0 client via client_credentials
 */
export function verifyOAuthClient(
  clientId: string,
  clientSecret: string
): { success: true; client: OAuthClient } | { success: false; error: string; status: number } {
  if (!clientId || !clientSecret) {
    return { success: false, status: 401, error: 'invalid_client: missing client_id or client_secret' };
  }

  const config = getConfig();
  if (config.environment !== 'production' && clientId === 'aeitron_test_client_id' && clientSecret === 'secret_test_key_889') {
    return {
      success: true,
      client: {
        clientId,
        clientSecretHash: '',
        tenantId: 'tenant_test_workspace',
        actorId: 'usr_test_client',
        scopes: ['account:read', 'projects:read', 'dns:read', 'usage:read']
      }
    };
  }

  const client = OAUTH_CLIENTS.get(clientId);
  if (!client) {
    return { success: false, status: 401, error: 'invalid_client: client not found or unauthorized' };
  }

  const inputSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');
  const expectedBuffer = Buffer.from(client.clientSecretHash, 'utf-8');
  const inputBuffer = Buffer.from(inputSecretHash, 'utf-8');

  if (expectedBuffer.length !== inputBuffer.length || !crypto.timingSafeEqual(expectedBuffer, inputBuffer)) {
    return { success: false, status: 401, error: 'invalid_client: client_secret verification failed' };
  }

  return { success: true, client };
}

/**
 * Extracts authentication token from standard HTTP headers or query parameters.
 * Automatically flags query parameters for audit warnings.
 */
export function extractTokenFromRequest(
  req: IncomingMessage,
  parsedUrl: URL
): { token?: string; wasInQuery: boolean } {
  // 1. Check Authorization header (Strongly preferred)
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const parts = authHeader.trim().split(/\s+/);
    if (parts.length === 2 && (parts[0].toLowerCase() === 'bearer' || parts[0].toLowerCase() === 'apikey')) {
      return { token: parts[1], wasInQuery: false };
    }
    return { token: authHeader.trim(), wasInQuery: false };
  }

  // 2. Check query parameters (for browser EventSource connections)
  const queryToken =
    parsedUrl.searchParams.get('token') ||
    parsedUrl.searchParams.get('apiKey') ||
    parsedUrl.searchParams.get('api_key') ||
    parsedUrl.searchParams.get('access_token');

  if (queryToken) {
    return { token: queryToken.trim(), wasInQuery: true };
  }

  return { token: undefined, wasInQuery: false };
}

/**
 * Cryptographically verifies an incoming authentication token (JWT or API Key).
 * Enforces mandatory claims for JWTs (exp, iss, aud, scopes) and fail-closed key validation.
 */
export function verifyAuthToken(
  token: string | undefined,
  options: {
    requiredScopes?: string[];
    jwtSecret?: string;
    isProduction?: boolean;
    allowSandbox?: boolean;
    expectedAudience?: string;
    expectedIssuer?: string;
  } = {}
): AuthResult {
  const config = getConfig();
  const isProd = options.isProduction ?? (config.environment === 'production');
  const allowSandbox = options.allowSandbox ?? config.allowSandbox;
  const jwtSecret = options.jwtSecret || config.jwtSecret;
  const expectedAud = options.expectedAudience || 'aeitron-mcp';
  const expectedIss = options.expectedIssuer || 'https://api.aeitron.com';

  if (!token || token.trim() === '') {
    return {
      success: false,
      status: 401,
      code: 'UNAUTHORIZED',
      error: 'Missing Authorization header or Bearer token.'
    };
  }

  // --------------------------------------------------------------------------
  // 1. Sandbox / Development Credentials
  // --------------------------------------------------------------------------
  if (token.startsWith('atk_sandbox_') || token.startsWith('atk_test_')) {
    if (isProd || !allowSandbox) {
      return {
        success: false,
        status: 401,
        code: 'SANDBOX_DISABLED_IN_PROD',
        error: 'Sandbox credentials are not permitted in production environments.'
      };
    }

    const claims: AuthClaims = {
      actorId: 'usr_sandbox_dev',
      tenantId: 'tenant_sandbox_workspace',
      tier: 'sandbox',
      scopes: [
        'account:read',
        'projects:read',
        'projects:write',
        'dns:read',
        'dns:write',
        'usage:read'
      ],
      livemode: false
    };

    return validateScopes(claims, token, options.requiredScopes);
  }

  // --------------------------------------------------------------------------
  // 2. JWT Cryptographic Verification (HMAC-SHA256)
  // --------------------------------------------------------------------------
  if (token.startsWith('eyJ') && token.split('.').length === 3) {
    const [headerB64, payloadB64, sigB64] = token.split('.');

    try {
      // A. Verify cryptographic signature
      const expectedSig = crypto
        .createHmac('sha256', jwtSecret)
        .update(`${headerB64}.${payloadB64}`)
        .digest('base64url');

      const sigBuffer = Buffer.from(sigB64, 'utf-8');
      const expectedBuffer = Buffer.from(expectedSig, 'utf-8');

      if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
        return {
          success: false,
          status: 401,
          code: 'INVALID_SIGNATURE',
          error: 'Cryptographic JWT signature verification failed.'
        };
      }

      // B. Decode header and payload
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8')) as Record<string, unknown>;
      if (header.alg !== 'HS256') {
        return {
          success: false,
          status: 401,
          code: 'UNSUPPORTED_ALGORITHM',
          error: `Unsupported signing algorithm '${header.alg}'. Only HS256 is accepted.`
        };
      }

      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8')) as Record<string, unknown>;

      // C. Mandatory Expiration Check (P1: exp must be present and valid)
      const nowSec = Math.floor(Date.now() / 1000);
      if (typeof payload.exp !== 'number') {
        return {
          success: false,
          status: 401,
          code: 'MISSING_EXP_CLAIM',
          error: 'JWT is missing mandatory numeric "exp" (expiration) claim.'
        };
      }
      if (payload.exp < nowSec) {
        return {
          success: false,
          status: 401,
          code: 'TOKEN_EXPIRED',
          error: 'Authorization token has expired. Please refresh your OAuth session.'
        };
      }

      // D. Not Before Check
      if (typeof payload.nbf === 'number' && payload.nbf > nowSec) {
        return {
          success: false,
          status: 401,
          code: 'TOKEN_NOT_YET_VALID',
          error: 'Authorization token is not yet valid.'
        };
      }

      // E. Mandatory Issuer Check (P1: iss must be present and trusted)
      if (typeof payload.iss !== 'string' || (payload.iss !== expectedIss && payload.iss !== 'aeitron-auth')) {
        return {
          success: false,
          status: 401,
          code: 'INVALID_ISSUER',
          error: `Untrusted or missing token issuer '${payload.iss}'. Expected '${expectedIss}'.`
        };
      }

      // F. Mandatory Audience Check (P1: aud must be present and match)
      if (typeof payload.aud !== 'string' || (payload.aud !== expectedAud && payload.aud !== 'https://api.aeitron.com/mcp')) {
        return {
          success: false,
          status: 401,
          code: 'INVALID_AUDIENCE',
          error: `Invalid or missing token audience '${payload.aud}'. Expected '${expectedAud}'.`
        };
      }

      // G. Mandatory Scopes Check (P1: fail-closed, no default read scopes)
      let scopes: string[] = [];
      if (Array.isArray(payload.scopes)) {
        scopes = payload.scopes as string[];
      } else if (typeof payload.scope === 'string') {
        scopes = (payload.scope as string).split(' ').filter(Boolean);
      } else {
        return {
          success: false,
          status: 401,
          code: 'MISSING_SCOPES_CLAIM',
          error: 'JWT is missing mandatory "scopes" or "scope" claim. Default privileges are prohibited.'
        };
      }

      if (scopes.length === 0) {
        return {
          success: false,
          status: 403,
          code: 'EMPTY_SCOPES',
          error: 'Token contains no granted permission scopes.'
        };
      }

      const claims: AuthClaims = {
        actorId: (payload.sub as string) || (payload.actor_id as string) || 'usr_jwt_user',
        tenantId: (payload.tenant_id as string) || (payload.org_id as string) || 'tenant_jwt_workspace',
        tier: (payload.tier as AuthClaims['tier']) || 'developer',
        scopes,
        livemode: payload.livemode !== false,
        expiresAt: payload.exp
      };

      return validateScopes(claims, token, options.requiredScopes);
    } catch {
      return {
        success: false,
        status: 401,
        code: 'MALFORMED_JWT',
        error: 'Malformed JWT structure or invalid base64 encoding.'
      };
    }
  }

  // --------------------------------------------------------------------------
  // 3. Authoritative Production API Key Verification (Hashed Store)
  // --------------------------------------------------------------------------
  const keyHash = crypto.createHash('sha256').update(token).digest('hex');
  const registered = AUTHORITATIVE_KEYS.get(keyHash);

  if (registered) {
    const claims: AuthClaims = {
      actorId: registered.actorId,
      tenantId: registered.tenantId,
      tier: registered.tier,
      scopes: registered.scopes,
      livemode: true
    };
    return validateScopes(claims, token, options.requiredScopes);
  }

  // --------------------------------------------------------------------------
  // 4. Development mode fallback key (strictly non-production)
  // --------------------------------------------------------------------------
  if (!isProd && allowSandbox && token === 'atk_sandbox_dev_default_key') {
    const claims: AuthClaims = {
      actorId: 'usr_dev_local',
      tenantId: 'tenant_local_dev',
      tier: 'developer',
      scopes: [
        'account:read',
        'projects:read',
        'projects:write',
        'dns:read',
        'dns:write',
        'usage:read'
      ],
      livemode: false
    };
    return validateScopes(claims, token, options.requiredScopes);
  }

  // Fail-Closed: Arbitrary unverified tokens or fake keys are strictly rejected
  return {
    success: false,
    status: 401,
    code: 'INVALID_CREDENTIALS',
    error: 'Unrecognized, unverified, or revoked Aeitron credentials.'
  };
}

/**
 * Validates whether granted scopes satisfy required scopes
 */
function validateScopes(
  claims: AuthClaims,
  token: string,
  requiredScopes?: string[]
): AuthResult {
  if (!requiredScopes || requiredScopes.length === 0) {
    return { success: true, token, claims };
  }

  const claimScopes = new Set(claims.scopes);
  for (const required of requiredScopes) {
    if (!claimScopes.has(required) && !claimScopes.has('*')) {
      return {
        success: false,
        status: 403,
        code: 'INSUFFICIENT_SCOPE',
        error: `Access denied: Token is missing required scope '${required}'. Granted scopes: [${claims.scopes.join(', ')}]`
      };
    }
  }

  return { success: true, token, claims };
}

/**
 * Enforces tool-level authorization.
 * Fail-Closed: If a tool has no mapped scope, it is DENIED rather than permitted.
 */
export function checkToolAuthorization(
  toolName: string,
  claims?: AuthClaims
): { authorized: boolean; error?: string } {
  const requiredScope = TOOL_SCOPES[toolName];
  if (!requiredScope) {
    return {
      authorized: false,
      error: `Security Error: Unmapped tool '${toolName}'. Fail-closed policy denies unmapped tools.`
    };
  }

  if (!claims) {
    return {
      authorized: false,
      error: `Authentication required: Tool '${toolName}' requires scope '${requiredScope}'.`
    };
  }

  const claimScopes = new Set(claims.scopes);
  if (!claimScopes.has(requiredScope) && !claimScopes.has('*')) {
    return {
      authorized: false,
      error: `Forbidden: Tool '${toolName}' requires scope '${requiredScope}'. Your granted scopes: [${claims.scopes.join(', ')}]`
    };
  }

  return { authorized: true };
}

/**
 * Issues a cryptographically signed, short-lived challenge token for high-risk DNS deletions.
 * Prevents autonomous self-approval by LLM prompts.
 */
export function issueDnsDeletionChallenge(
  tenantId: string,
  domain: string,
  recordId: string,
  secret?: string
): { token: string; expiresAt: number } {
  const config = getConfig();
  const signingSecret = secret || config.jwtSecret;
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minute validity window

  const payload = JSON.stringify({
    action: 'dns_delete_challenge',
    tenantId,
    domain,
    recordId,
    expiresAt
  });

  const payloadB64 = Buffer.from(payload).toString('base64url');
  const signature = crypto
    .createHmac('sha256', signingSecret)
    .update(`del:${payloadB64}`)
    .digest('base64url');

  return {
    token: `del_tok_${payloadB64}.${signature}`,
    expiresAt
  };
}

/**
 * Verifies a DNS deletion approval challenge token
 */
export function verifyDnsDeletionChallenge(
  challengeToken: string,
  expectedTenantId: string,
  expectedDomain: string,
  expectedRecordId: string,
  secret?: string
): { valid: boolean; error?: string } {
  if (!challengeToken || !challengeToken.startsWith('del_tok_')) {
    return { valid: false, error: 'Invalid challenge token format. Expected "del_tok_..." token.' };
  }

  const raw = challengeToken.slice('del_tok_'.length);
  const parts = raw.split('.');
  if (parts.length !== 2) {
    return { valid: false, error: 'Malformed challenge token structure.' };
  }

  const [payloadB64, signature] = parts;
  const config = getConfig();
  const signingSecret = secret || config.jwtSecret;

  const expectedSig = crypto
    .createHmac('sha256', signingSecret)
    .update(`del:${payloadB64}`)
    .digest('base64url');

  const sigBuffer = Buffer.from(signature, 'utf-8');
  const expectedBuffer = Buffer.from(expectedSig, 'utf-8');

  if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    return { valid: false, error: 'Cryptographic challenge token signature mismatch.' };
  }

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    if (payload.action !== 'dns_delete_challenge') {
      return { valid: false, error: 'Invalid challenge action payload.' };
    }
    if (Date.now() > payload.expiresAt) {
      return { valid: false, error: 'Challenge approval token has expired (5-minute TTL exceeded).' };
    }
    if (payload.domain !== expectedDomain || payload.recordId !== expectedRecordId) {
      return { valid: false, error: 'Challenge approval token does not match target domain or record ID.' };
    }
    if (expectedTenantId !== 'anonymous' && payload.tenantId !== expectedTenantId) {
      return { valid: false, error: 'Challenge approval token tenant mismatch.' };
    }
    return { valid: true };
  } catch {
    return { valid: false, error: 'Failed to decode challenge token payload.' };
  }
}

/**
 * Helper to generate cryptographically signed test JWTs for testing & OAuth flows
 */
export function createSignedTestJwt(
  payload: Record<string, unknown>,
  secret?: string
): string {
  const config = getConfig();
  const signingSecret = secret || config.jwtSecret;

  const headerB64 = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify({
    iss: 'https://api.aeitron.com',
    aud: 'aeitron-mcp',
    exp: Math.floor(Date.now() / 1000) + 3600,
    scopes: ['account:read', 'projects:read', 'dns:read', 'usage:read'],
    ...payload
  })).toString('base64url');

  const signature = crypto
    .createHmac('sha256', signingSecret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Returns RFC 8414 OAuth 2.0 Authorization Server Metadata
 */
export function getOAuthDiscoveryMetadata(publicBaseUrl: string): Record<string, unknown> {
  const issuer = publicBaseUrl.replace(/\/+$/, '');
  return {
    issuer,
    authorization_endpoint: 'https://console.aeitron.com/oauth/authorize',
    token_endpoint: `${issuer}/v1/auth/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    registration_endpoint: 'https://console.aeitron.com/settings/api-keys',
    scopes_supported: [
      'account:read',
      'projects:read',
      'projects:write',
      'dns:read',
      'dns:write',
      'dns:write:delete',
      'usage:read'
    ],
    response_types_supported: ['token'],
    grant_types_supported: ['client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    service_documentation: 'https://docs.aeitron.com/mcp'
  };
}

/**
 * Returns RFC 7517 compliant JSON Web Key Set (JWKS) metadata
 */
export function getJwksMetadata(): { keys: Array<Record<string, unknown>> } {
  return {
    keys: [
      {
        kty: 'oct',
        use: 'sig',
        alg: 'HS256',
        kid: 'aeitron-mcp-key-2026-v1'
      }
    ]
  };
}
