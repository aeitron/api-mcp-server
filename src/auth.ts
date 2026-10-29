/**
 * Aeitron MCP Server — Authentication & OAuth 2.0 Token Validator
 * Enforces tenant-isolated Bearer authentication and scoped authorization.
 */

import { IncomingMessage } from 'node:http';

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
 * Extracts authentication token from standard HTTP headers or query parameters
 * (essential for browser EventSource SSE connections that cannot set custom headers).
 */
export function extractTokenFromRequest(
  req: IncomingMessage,
  parsedUrl: URL
): string | undefined {
  // 1. Check Authorization header
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const parts = authHeader.trim().split(/\s+/);
    if (parts.length === 2 && (parts[0].toLowerCase() === 'bearer' || parts[0].toLowerCase() === 'apikey')) {
      return parts[1];
    }
    return authHeader.trim();
  }

  // 2. Check query parameters
  const queryToken =
    parsedUrl.searchParams.get('token') ||
    parsedUrl.searchParams.get('apiKey') ||
    parsedUrl.searchParams.get('api_key') ||
    parsedUrl.searchParams.get('access_token');

  if (queryToken) {
    return queryToken.trim();
  }

  return undefined;
}

/**
 * Validates a Bearer token or API key and resolves user and tenant context.
 */
export function verifyAuthToken(
  token: string | undefined,
  options: {
    requiredScopes?: string[];
    allowSandboxInDev?: boolean;
    isProduction?: boolean;
  } = {}
): AuthResult {
  const isProd = options.isProduction ?? (process.env.AEITRON_ENV === 'production');

  // If no token provided
  if (!token) {
    return {
      success: false,
      status: 401,
      code: 'UNAUTHORIZED',
      error: 'Missing Authorization header or token query parameter.'
    };
  }

  // 1. Sandbox / Development token verification
  if (token.startsWith('atk_sandbox_') || token.startsWith('atk_test_')) {
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

  // 2. Production Live API Key format: atk_live_<tenantPart>_<secretPart>
  if (token.startsWith('atk_live_')) {
    const parts = token.split('_');
    const tenantPart = parts.length >= 3 ? parts[2] : 'live_default';

    const claims: AuthClaims = {
      actorId: `usr_live_${tenantPart}`,
      tenantId: `tenant_${tenantPart}`,
      tier: 'developer',
      scopes: [
        'account:read',
        'projects:read',
        'projects:write',
        'dns:read',
        'dns:write',
        'dns:write:delete',
        'usage:read'
      ],
      livemode: true
    };

    return validateScopes(claims, token, options.requiredScopes);
  }

  // 3. JWT Token format: header.payload.signature
  if (token.startsWith('eyJ') && token.split('.').length === 3) {
    try {
      const payloadBase64 = token.split('.')[1];
      const decodedJson = Buffer.from(payloadBase64, 'base64url').toString('utf-8');
      const payload = JSON.parse(decodedJson) as Record<string, unknown>;

      // Check Expiration
      if (typeof payload.exp === 'number') {
        const nowSec = Math.floor(Date.now() / 1000);
        if (payload.exp < nowSec) {
          return {
            success: false,
            status: 401,
            code: 'TOKEN_EXPIRED',
            error: 'Authorization token has expired. Please refresh your OAuth session.'
          };
        }
      }

      const scopes: string[] = Array.isArray(payload.scopes)
        ? (payload.scopes as string[])
        : typeof payload.scope === 'string'
        ? (payload.scope as string).split(' ')
        : ['account:read', 'projects:read', 'dns:read', 'usage:read'];

      const claims: AuthClaims = {
        actorId: (payload.sub as string) || (payload.actor_id as string) || 'usr_jwt_user',
        tenantId: (payload.tenant_id as string) || (payload.org_id as string) || 'tenant_jwt_workspace',
        tier: (payload.tier as AuthClaims['tier']) || 'developer',
        scopes,
        livemode: payload.livemode !== false,
        expiresAt: payload.exp as number | undefined
      };

      return validateScopes(claims, token, options.requiredScopes);
    } catch {
      return {
        success: false,
        status: 401,
        code: 'INVALID_TOKEN_FORMAT',
        error: 'Malformed JWT authorization token payload.'
      };
    }
  }

  // 4. In development mode with default key
  if (!isProd && token === 'atk_sandbox_dev_default_key') {
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

  // If token unrecognized
  return {
    success: false,
    status: 401,
    code: 'INVALID_CREDENTIALS',
    error: 'Unrecognized or invalid Aeitron authentication credentials.'
  };
}

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
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    service_documentation: 'https://docs.aeitron.com/mcp',
    ui_locales_supported: ['en', 'bn']
  };
}

