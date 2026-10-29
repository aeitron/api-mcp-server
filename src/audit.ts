/**
 * Aeitron MCP Server — Structured Audit & Security Sanitizer
 */

import { AuditRecord } from './types.js';

const SENSITIVE_PATTERNS = [
  'password',
  'secret',
  'token',
  'apikey',
  'auth',
  'privatekey',
  'cert',
  'signature',
  'creditcard',
  'cvv'
];

/**
 * Deeply sanitizes arbitrary objects or payloads to prevent leaking credentials
 * into audit logs or LLM context windows.
 */
export function sanitizePayload<T>(input: T): T {
  if (input === null || input === undefined) {
    return input;
  }

  if (typeof input === 'string') {
    // Redact Bearer tokens if found in raw text
    if (/Bearer\s+[a-zA-Z0-9._~+/-]+=*/i.test(input)) {
      return input.replace(/Bearer\s+[a-zA-Z0-9._~+/-]+=*/gi, 'Bearer [REDACTED]') as unknown as T;
    }
    return input;
  }

  if (Array.isArray(input)) {
    return input.map(item => sanitizePayload(item)) as unknown as T;
  }

  if (typeof input === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(input as Record<string, unknown>)) {
      const normalizedKey = key.toLowerCase().replace(/[-_\s]/g, '');
      const isSensitive = SENSITIVE_PATTERNS.some(pat => normalizedKey.includes(pat));

      if (isSensitive) {
        output[key] = '[REDACTED]';
      } else {
        output[key] = sanitizePayload(val);
      }
    }
    return output as T;
  }

  return input;
}

export class AuditLogger {
  private logSink: (record: AuditRecord) => void;

  constructor(sink?: (record: AuditRecord) => void) {
    this.logSink = sink || ((record: AuditRecord) => {
      // In production/CLI, logs are formatted as single-line JSON on stderr
      // (preserving stdout exclusively for stdio MCP JSON-RPC protocol)
      process.stderr.write(JSON.stringify(record) + '\n');
    });
  }

  public logToolExecution(
    tool: string,
    input: Record<string, unknown>,
    durationMs: number,
    success: boolean,
    context?: { tenantId?: string; actorId?: string },
    error?: unknown
  ): AuditRecord {
    const record: AuditRecord = {
      timestamp: new Date().toISOString(),
      tool,
      tenantId: context?.tenantId || 'anonymous_tenant',
      actorId: context?.actorId || 'ai_client',
      durationMs: Math.round(durationMs),
      success,
      input: sanitizePayload(input),
      error: error instanceof Error ? error.message : error ? String(error) : undefined
    };

    try {
      this.logSink(record);
    } catch {
      // Never crash tool execution if logging sink encounters I/O failure
    }

    return record;
  }
}
