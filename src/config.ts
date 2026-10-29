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
  rawApiKeys?: string;
  rawOAuthClients?: string;
}

export function getConfig(): McpServerConfig {
  const rawEnv = (process.env.AEITRON_ENV || 'development').trim().toLowerCase();
  
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

  const isProd = environment === 'production';

  // 1. Strict Fail-Closed Mock Fallback Guard
  const explicitMock = process.env.AEITRON_MOCK_FALLBACK;
  if (isProd && explicitMock === 'true') {
    throw new Error('FATAL CONFIGURATION ERROR: AEITRON_MOCK_FALLBACK cannot be enabled in production.');
  }
  const mockFallback = isProd ? false : explicitMock === 'true';

  // 2. Cryptographic JWT Secret
  const jwtSecret = process.env.AEITRON_JWT_SECRET || (isProd ? '' : 'aeitron_dev_jwt_secret_do_not_use_in_prod_1234567890');
  if (isProd && (!jwtSecret || jwtSecret.length < 32)) {
    throw new Error('FATAL CONFIGURATION ERROR: AEITRON_JWT_SECRET must be at least 32 characters in production.');
  }

  // 3. CORS Allowed Origins
  const rawCors = process.env.AEITRON_CORS_ORIGINS;
  const corsAllowedOrigins = rawCors
    ? rawCors.split(',').map((s) => s.trim()).filter(Boolean)
    : isProd
    ? ['https://chatgpt.com', 'https://claude.ai', 'https://console.aeitron.com', 'https://api.aeitron.com']
    : ['*'];

  // 4. Sandbox Credentials Allowed (Only in non-production)
  const allowSandbox = !isProd && process.env.AEITRON_ALLOW_SANDBOX !== 'false';

  return {
    apiBaseUrl: (process.env.AEITRON_API_BASE_URL || 'http://localhost:8080').replace(/\/+$/, ''),
    defaultApiKey: process.env.AEITRON_API_KEY || (isProd ? undefined : 'atk_sandbox_dev_default_key'),
    environment,
    mockFallback,
    requestTimeoutMs: parseInt(process.env.AEITRON_REQUEST_TIMEOUT_MS || '8000', 10),
    jwtSecret,
    corsAllowedOrigins,
    allowSandbox,
    rawApiKeys: process.env.AEITRON_API_KEYS,
    rawOAuthClients: process.env.AEITRON_OAUTH_CLIENTS
  };
}
