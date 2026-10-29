/**
 * Aeitron MCP Server — Configuration & Environment Parser
 */

export interface McpServerConfig {
  apiBaseUrl: string;
  defaultApiKey?: string;
  environment: 'development' | 'staging' | 'production';
  mockFallback: boolean;
  requestTimeoutMs: number;
}

export function getConfig(): McpServerConfig {
  const env = process.env.AEITRON_ENV || 'development';
  const isProd = env === 'production';

  return {
    apiBaseUrl: (process.env.AEITRON_API_BASE_URL || 'http://localhost:8080').replace(/\/+$/, ''),
    defaultApiKey: process.env.AEITRON_API_KEY || (isProd ? undefined : 'atk_sandbox_dev_default_key'),
    environment: (env === 'production' || env === 'staging') ? env : 'development',
    // In dev or tests, mock fallback allows graceful testing without requiring live upstream
    mockFallback: process.env.AEITRON_MOCK_FALLBACK !== 'false',
    requestTimeoutMs: parseInt(process.env.AEITRON_REQUEST_TIMEOUT_MS || '8000', 10)
  };
}

