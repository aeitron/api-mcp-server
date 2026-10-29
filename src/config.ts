/**
 * Aeitron MCP Server — Hardened Configuration & Environment Parser
 * Enforces fail-closed production boundaries: zero mock fallback in production,
 * required cryptographic secrets, strict environment parsing, and explicit CORS origin policies.
 */

export interface McpServerConfig {
  apiBaseUrl: string;
  defaultApiKey?: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  mockFallback: boolean;
  requestTimeoutMs: number;
  jwtSecret: string;
  corsAllowedOrigins: string[];
  allowSandbox: boolean;
  sessionIdleTimeoutMs: number;
  maxActiveSessions: number;
  storageDir: string;
  rawApiKeys?: string;
  rawOAuthClients?: string;
}

export function getConfig(): McpServerConfig {
  const nodeEnv = (process.env.NODE_ENV || '').trim().toLowerCase();
  const rawAeitronEnv = process.env.AEITRON_ENV ? process.env.AEITRON_ENV.trim().toLowerCase() : undefined;

  let rawEnv: string;
  if (rawAeitronEnv) {
    // Conflict detection: if NODE_ENV is production but AEITRON_ENV claims non-production (dev, test, etc.), fail closed
    const isNodeProd = nodeEnv === 'production' || nodeEnv === 'prod';
    const isAeitronProdLike = rawAeitronEnv === 'production' || rawAeitronEnv === 'prod' || rawAeitronEnv === 'staging' || rawAeitronEnv === 'stage';
    if (isNodeProd && !isAeitronProdLike) {
      throw new Error(`FATAL CONFIGURATION ERROR: Conflicting environment configuration. NODE_ENV is 'production' but AEITRON_ENV is '${rawAeitronEnv}'. Explicitly align or configure AEITRON_ENV.`);
    }
    rawEnv = rawAeitronEnv;
  } else if (nodeEnv === 'production' || nodeEnv === 'prod') {
    // When deployed in a production container without explicit AEITRON_ENV, fail-safely default to production
    rawEnv = 'production';
  } else if (nodeEnv === 'test') {
    rawEnv = 'test';
  } else {
    rawEnv = 'development';
  }
  
  let environment: 'development' | 'staging' | 'production' | 'test';
  if (rawEnv === 'production' || rawEnv === 'prod') {
    environment = 'production';
  } else if (rawEnv === 'staging' || rawEnv === 'stage') {
    environment = 'staging';
  } else if (rawEnv === 'development' || rawEnv === 'dev') {
    environment = 'development';
  } else if (rawEnv === 'test') {
    environment = 'test';
  } else {
    // Fail-Closed: Unrecognized environment must not default to development
    throw new Error(`FATAL CONFIGURATION ERROR: Invalid AEITRON_ENV '${rawEnv}'. Permitted environments: development, staging, production, test.`);
  }

  const isHardened = environment === 'production' || environment === 'staging';

  // 1. Strict Fail-Closed Mock Fallback Guard (prohibited in production and staging)
  const explicitMock = process.env.AEITRON_MOCK_FALLBACK;
  if (isHardened && explicitMock === 'true') {
    throw new Error(`FATAL CONFIGURATION ERROR: AEITRON_MOCK_FALLBACK cannot be enabled in ${environment}.`);
  }
  const mockFallback = isHardened ? false : explicitMock === 'true';

  // 2. Cryptographic JWT Secret (strictly required in production and staging)
  const jwtSecret = process.env.AEITRON_JWT_SECRET || (isHardened ? '' : 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890');
  if (isHardened && (!jwtSecret || jwtSecret.length < 32)) {
    throw new Error(`FATAL CONFIGURATION ERROR: AEITRON_JWT_SECRET must be at least 32 characters in ${environment}.`);
  }

  // 3. CORS Allowed Origins
  const rawCors = process.env.AEITRON_CORS_ORIGINS;
  const corsAllowedOrigins = rawCors
    ? rawCors.split(',').map((s) => s.trim()).filter(Boolean)
    : isHardened
    ? ['https://chatgpt.com', 'https://claude.ai', 'https://console.aeitron.com', 'https://api.aeitron.com']
    : ['*'];

  // 4. Sandbox Credentials Allowed (Only in development and test)
  const allowSandbox = !isHardened && process.env.AEITRON_ALLOW_SANDBOX !== 'false';

  return {
    apiBaseUrl: (process.env.AEITRON_API_BASE_URL || 'http://localhost:8080').replace(/\/+$/, ''),
    defaultApiKey: process.env.AEITRON_API_KEY || (isHardened ? undefined : 'atk_sandbox_dev_default_key'),
    environment,
    mockFallback,
    requestTimeoutMs: parseInt(process.env.AEITRON_REQUEST_TIMEOUT_MS || '8000', 10),
    jwtSecret,
    corsAllowedOrigins,
    allowSandbox,
    sessionIdleTimeoutMs: parseInt(process.env.AEITRON_SESSION_IDLE_TIMEOUT_MS || '1800000', 10), // 30 minutes default
    maxActiveSessions: parseInt(process.env.AEITRON_MAX_ACTIVE_SESSIONS || '100', 10),
    storageDir: process.env.AEITRON_STORAGE_DIR || process.env.AEITRON_STATE_DIR || '',
    rawApiKeys: process.env.AEITRON_API_KEYS,
    rawOAuthClients: process.env.AEITRON_OAUTH_CLIENTS
  };
}
