import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizePayload, AuditLogger } from '../src/audit.js';
import { AuditRecord } from '../src/types.js';

describe('Audit & Sanitizer Suite', () => {
  it('deeply redacts sensitive keys from audit payloads', () => {
    const raw = {
      username: 'alice',
      password: 'superSecretPassword123',
      apiKey: 'atk_live_9942a1bc',
      nested: {
        token: 'eyJh...jwtToken',
        client_secret: 'sec_123',
        normalField: 'safeValue',
        bearerString: 'Authorization: Bearer sk-secret-12345 in text'
      },
      list: [
        { key: 'safe' },
        { private_key: '-----BEGIN RSA PRIVATE KEY-----' }
      ]
    };

    const sanitized = sanitizePayload(raw);

    assert.equal(sanitized.username, 'alice');
    assert.equal(sanitized.password, '[REDACTED]');
    assert.equal(sanitized.apiKey, '[REDACTED]');
    assert.equal(sanitized.nested.normalField, 'safeValue');
    assert.equal(sanitized.nested.token, '[REDACTED]');
    assert.equal(sanitized.nested.client_secret, '[REDACTED]');
    assert.equal(sanitized.nested.bearerString, 'Authorization: Bearer [REDACTED] in text');
    assert.equal(sanitized.list[1].private_key, '[REDACTED]');
  });

  it('records structured audit entries through AuditLogger', () => {
    const captured: AuditRecord[] = [];
    const logger = new AuditLogger((record) => captured.push(record));

    logger.logToolExecution(
      'get_dns_records',
      { domain: 'example.com', apiKey: 'secret_to_hide' },
      45.2,
      true,
      { tenantId: 'tenant_123', actorId: 'user_456' }
    );

    assert.equal(captured.length, 1);
    const log = captured[0];
    assert.equal(log.tool, 'get_dns_records');
    assert.equal(log.tenantId, 'tenant_123');
    assert.equal(log.actorId, 'user_456');
    assert.equal(log.success, true);
    assert.equal(log.input.domain, 'example.com');
    assert.equal(log.input.apiKey, '[REDACTED]');
    assert.ok(log.durationMs >= 45);
    assert.ok(typeof log.timestamp === 'string');
  });
});

