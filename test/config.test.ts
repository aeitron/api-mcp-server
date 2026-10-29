import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { getConfig } from '../src/config.js';

describe('Environment & Docker Configuration Suite', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.NODE_ENV;
    delete process.env.AEITRON_ENV;
    delete process.env.AEITRON_JWT_SECRET;
    delete process.env.AEITRON_MOCK_FALLBACK;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('1. Docker Production Default: NODE_ENV=production without AEITRON_ENV resolves to production', () => {
    process.env.NODE_ENV = 'production';
    process.env.AEITRON_JWT_SECRET = 'a_very_secure_production_secret_key_at_least_32_chars!';
    
    const config = getConfig();
    assert.equal(config.environment, 'production');
    assert.equal(config.mockFallback, false);
    assert.equal(config.allowSandbox, false);
    assert.equal(config.defaultApiKey, undefined);
  });

  it('2. Fail-Closed on Conflict: NODE_ENV=production with AEITRON_ENV=development throws fatal error', () => {
    process.env.NODE_ENV = 'production';
    process.env.AEITRON_ENV = 'development';

    assert.throws(
      () => getConfig(),
      /Conflicting environment configuration/
    );
  });

  it('2b. Fail-Closed on Conflict: NODE_ENV=production with AEITRON_ENV=test throws fatal error', () => {
    process.env.NODE_ENV = 'production';
    process.env.AEITRON_ENV = 'test';

    assert.throws(
      () => getConfig(),
      /Conflicting environment configuration/
    );
  });

  it('2c. Fail-Closed on Conflict: NODE_ENV=production with AEITRON_ENV=testing or sandbox throws fatal error', () => {
    process.env.NODE_ENV = 'production';
    process.env.AEITRON_ENV = 'testing';

    assert.throws(
      () => getConfig(),
      /Conflicting environment configuration/
    );

    process.env.AEITRON_ENV = 'sandbox';
    assert.throws(
      () => getConfig(),
      /Conflicting environment configuration/
    );
  });

  it('3. Fail-Closed on Staging: requires >=32 char secret and strictly disables sandbox', () => {
    process.env.AEITRON_ENV = 'staging';
    
    // Missing secret must throw
    assert.throws(
      () => getConfig(),
      /AEITRON_JWT_SECRET must be at least 32 characters in staging/
    );

    // With valid secret
    process.env.AEITRON_JWT_SECRET = 'staging_secure_cryptographic_secret_32chars!';
    const config = getConfig();
    assert.equal(config.environment, 'staging');
    assert.equal(config.mockFallback, false);
    assert.equal(config.allowSandbox, false);
    assert.equal(config.defaultApiKey, undefined);
  });

  it('4. Fail-Closed on Production: AEITRON_MOCK_FALLBACK=true is strictly prohibited', () => {
    process.env.AEITRON_ENV = 'production';
    process.env.AEITRON_JWT_SECRET = 'a_very_secure_production_secret_key_at_least_32_chars!';
    process.env.AEITRON_MOCK_FALLBACK = 'true';

    assert.throws(
      () => getConfig(),
      /AEITRON_MOCK_FALLBACK cannot be enabled in production/
    );
  });

  it('5. Fail-Closed on Unknown Environment: rejects arbitrary strings without defaulting to dev', () => {
    process.env.AEITRON_ENV = 'arbitrary_invalid_environment_string';

    assert.throws(
      () => getConfig(),
      /Invalid AEITRON_ENV/
    );
  });
});

