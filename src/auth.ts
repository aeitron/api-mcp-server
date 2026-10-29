/**
 * Aeitron MCP Server — Cryptographic Authentication & Authorization Engine
 * Enforces fail-closed token validation, HMAC-SHA256 signature verification,
 * dynamic authoritative API key checking, mandatory JWT claims, and tool-level RBAC scopes.
 */

import { IncomingMessage } from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
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
 * Active Key ID for JWT signing and JWKS distribution
 */
export const ACTIVE_KID = process.env.AEITRON_JWT_KID || 'aeitron-mcp-rsa-2026-v1';

/**
 * Registry of authoritative live API keys.
 * Zero hardcoded keys in production. Keys are loaded dynamically from environment or hashed store.
 */
const AUTHORITATIVE_KEYS = new Map<string, RegisteredKey>();
const OAUTH_CLIENTS = new Map<string, OAuthClient>();

export function isHardenedEnvironment(): boolean {
  const env = (process.env.AEITRON_ENV || process.env.NODE_ENV || '').trim().toLowerCase();
  return env === 'production' || env === 'prod' || env === 'staging' || env === 'stage';
}

function getStorageDir(): string {
  const config = getConfig();
  const configured = (config.storageDir || process.env.AEITRON_STORAGE_DIR || process.env.AEITRON_STATE_DIR || '').trim();
  if (configured) {
    return configured;
  }
  return path.join(process.cwd(), '.aeitron-state');
}

function ensureStorageDir(): string {
  const dir = getStorageDir();
  try {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  } catch (err) {
    if (isHardenedEnvironment()) {
      throw new Error(`CRITICAL: Failed to initialize persistent storage directory '${dir}' in hardened environment: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return dir;
}

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

interface RsaKeyPair {
  publicKey: string;
  privateKey: string;
}

interface RegisteredPublicKey {
  kid: string;
  publicKeyPem: string;
  keyObject: crypto.KeyObject;
  jwk: Record<string, unknown>;
  active: boolean;
  addedAt: number;
}

const REGISTERED_PUBLIC_KEYS = new Map<string, RegisteredPublicKey>();

export function verifyRsaKeyPairMatch(privateKeyPem: string, publicKeyPem: string): boolean {
  try {
    const privKey = crypto.createPrivateKey(privateKeyPem);
    const derivedPub = crypto.createPublicKey(privKey);
    const pubKey = crypto.createPublicKey(publicKeyPem);

    const derivedDer = derivedPub.export({ type: 'spki', format: 'der' });
    const pubDer = pubKey.export({ type: 'spki', format: 'der' });
    return crypto.timingSafeEqual(derivedDer, pubDer);
  } catch {
    return false;
  }
}

// Asymmetric Key Pair for RFC 7517 compliant JWKS public key distribution and RS256 signing
export function loadOrGenerateRsaKeyPair(): RsaKeyPair {
  // Guard: Configured RSA key file must exist in hardened environments
  const configuredKeyFile = process.env.AEITRON_RSA_KEY_FILE || process.env.AEITRON_JWT_KEY_FILE;
  if (configuredKeyFile && isHardenedEnvironment()) {
    if (!fs.existsSync(configuredKeyFile)) {
      throw new Error(`CRITICAL: Configured RSA key file does not exist: ${configuredKeyFile}`);
    }
  }

  // 1. Direct environment variable support (standard 12-factor / KMS / secret manager)
  const envPrivate = process.env.AEITRON_RSA_PRIVATE_KEY || process.env.AEITRON_JWT_PRIVATE_KEY;
  const envPublic = process.env.AEITRON_RSA_PUBLIC_KEY || process.env.AEITRON_JWT_PUBLIC_KEY;

  if (!envPrivate && envPublic && isHardenedEnvironment()) {
    throw new Error('CRITICAL CONFIGURATION ERROR: RSA public key is configured without a corresponding private signing key.');
  }

  if (envPrivate) {
    if (envPublic) {
      if (!verifyRsaKeyPairMatch(envPrivate, envPublic)) {
        if (isHardenedEnvironment()) {
          throw new Error('CRITICAL CONFIGURATION ERROR: Supplied AEITRON_RSA_PUBLIC_KEY does not correspond to AEITRON_RSA_PRIVATE_KEY.');
        }
        process.stderr.write('[aeitron-mcp][WARN] AEITRON_RSA_PUBLIC_KEY does not correspond to AEITRON_RSA_PRIVATE_KEY. Deriving public key from private key.\n');
        try {
          const privKey = crypto.createPrivateKey(envPrivate);
          const derivedPub = crypto.createPublicKey(privKey).export({ type: 'spki', format: 'pem' }) as string;
          return { privateKey: envPrivate, publicKey: derivedPub };
        } catch {
          // Fall through
        }
      } else {
        return { privateKey: envPrivate, publicKey: envPublic };
      }
    } else {
      // Automatically derive corresponding public key from private key
      try {
        const privKey = crypto.createPrivateKey(envPrivate);
        const derivedPub = crypto.createPublicKey(privKey).export({ type: 'spki', format: 'pem' }) as string;
        return { privateKey: envPrivate, publicKey: derivedPub };
      } catch (err) {
        if (isHardenedEnvironment()) {
          throw new Error(`CRITICAL: Malformed AEITRON_RSA_PRIVATE_KEY in hardened environment: ${String(err)}`);
        }
      }
    }
  }

  // 2. Persistent Key File from AEITRON_RSA_KEY_FILE / AEITRON_JWT_KEY_FILE
  const keyFilePath = process.env.AEITRON_RSA_KEY_FILE || process.env.AEITRON_JWT_KEY_FILE;
  if (keyFilePath) {
    if (!fs.existsSync(keyFilePath)) {
      if (isHardenedEnvironment()) {
        throw new Error(`CRITICAL CONFIGURATION ERROR: Configured RSA key file '${keyFilePath}' does not exist.`);
      }
    } else {
      try {
        const fileContent = fs.readFileSync(keyFilePath, 'utf-8');
        const parsed = JSON.parse(fileContent);
        if (parsed.privateKey && parsed.publicKey) {
          if (!verifyRsaKeyPairMatch(parsed.privateKey, parsed.publicKey)) {
            if (isHardenedEnvironment()) {
              throw new Error(`CRITICAL CONFIGURATION ERROR: Key pair in '${keyFilePath}' does not match.`);
            }
          } else {
            return { privateKey: parsed.privateKey, publicKey: parsed.publicKey };
          }
        }
      } catch (err) {
        if (isHardenedEnvironment()) {
          throw new Error(`CRITICAL: Failed to load RSA key file '${keyFilePath}' in hardened environment: ${String(err)}`);
        }
      }
    }
  }

  // 3. Persistent Local Storage Cache (preserves identical key pair across server restarts & multi-process CLI)
  const stateDir = ensureStorageDir();
  const cachedKeyFile = path.join(stateDir, 'aeitron-jwt-rsa.json');
  try {
    if (fs.existsSync(cachedKeyFile)) {
      const cachedContent = fs.readFileSync(cachedKeyFile, 'utf-8');
      const cached = JSON.parse(cachedContent);
      if (cached.privateKey && cached.publicKey) {
        if (verifyRsaKeyPairMatch(cached.privateKey, cached.publicKey)) {
          return { privateKey: cached.privateKey, publicKey: cached.publicKey };
        }
      }
    }
  } catch {
    // Corrupt cache file, fall through
  }

  // 4. Generate new RSA-2048 key pair
  const generated = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  // Persist generated key pair to local storage cache atomically
  try {
    const tempFile = `${cachedKeyFile}.tmp.${Date.now()}`;
    fs.writeFileSync(
      tempFile,
      JSON.stringify({ privateKey: generated.privateKey, publicKey: generated.publicKey, generatedAt: Date.now() }, null, 2),
      { encoding: 'utf-8', mode: 0o600 }
    );
    fs.renameSync(tempFile, cachedKeyFile);
  } catch (err) {
    if (isHardenedEnvironment()) {
      throw new Error(`CRITICAL: Failed to persist generated RSA key pair to '${cachedKeyFile}' in hardened environment: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return generated;
}

const RSA_KEY_PAIR = loadOrGenerateRsaKeyPair();

function registerPublicKey(kid: string, publicKeyPem: string, active: boolean): void {
  try {
    const keyObject = crypto.createPublicKey(publicKeyPem);
    const jwk = keyObject.export({ format: 'jwk' });
    REGISTERED_PUBLIC_KEYS.set(kid, {
      kid,
      publicKeyPem,
      keyObject,
      jwk,
      active,
      addedAt: Date.now()
    });
  } catch {
    // Ignore malformed key registration
  }
}

// Register primary active RSA public key
registerPublicKey(ACTIVE_KID, RSA_KEY_PAIR.publicKey, true);

// Load any historical rotated public keys from environment for graceful key rotation
function loadHistoricalKeysFromEnv(): void {
  const rawHistorical = process.env.AEITRON_HISTORICAL_PUBLIC_KEYS;
  if (!rawHistorical) return;
  try {
    const parsed = JSON.parse(rawHistorical);
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (item.kid && item.publicKey) {
          registerPublicKey(item.kid, item.publicKey, false);
        }
      }
    }
  } catch {
    // Fall through
  }
}
loadHistoricalKeysFromEnv();

/**
 * Register a historical public key in-memory for testing key rotation
 */
export function registerHistoricalRsaKeyForTesting(kid: string, publicKeyPem: string): void {
  registerPublicKey(kid, publicKeyPem, false);
}

// Synchronous sleep helper for atomic lock backoff
function sleepSync(ms: number): void {
  try {
    const sab = new SharedArrayBuffer(4);
    const int32 = new Int32Array(sab);
    Atomics.wait(int32, 0, 0, ms);
  } catch {
    const end = Date.now() + ms;
    while (Date.now() < end) {}
  }
}

/**
 * Cross-process atomic lock using exclusive lockfile flag 'wx'.
 * Handles stale locks (>10s old) and retries with backoff up to 5000ms.
 */
function acquireDnsStateLock(): () => void {
  const dir = ensureStorageDir();
  const lockPath = path.join(dir, 'dns-deletion-state.lock');
  const maxWaitMs = 5000;
  const start = Date.now();
  let fd: number | null = null;

  while (Date.now() - start < maxWaitMs) {
    try {
      fd = fs.openSync(lockPath, 'wx');
      fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, createdAt: Date.now() }));
      break;
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code;
      if (code === 'EEXIST' || code === 'EBUSY') {
        try {
          const stats = fs.statSync(lockPath);
          if (Date.now() - stats.mtimeMs > 10000) {
            try {
              fs.unlinkSync(lockPath);
            } catch {}
          }
        } catch {}
        sleepSync(20);
        continue;
      }
      throw err;
    }
  }

  if (fd === null) {
    throw new Error('TIMEOUT: Failed to acquire DNS state lock within 5000ms.');
  }

  return () => {
    try {
      if (fd !== null) {
        fs.closeSync(fd);
      }
    } catch {}
    try {
      fs.unlinkSync(lockPath);
    } catch {}
  };
}

export function withDnsStateLock<T>(fn: () => T): T {
  const release = acquireDnsStateLock();
  try {
    return fn();
  } finally {
    release();
  }
}

export type DnsDeletionStatus = 'pending' | 'approved' | 'executing' | 'completed' | 'failed';

// Pending deletion requests awaiting human operator approval
export interface PendingDeletionRequest {
  requestId: string;
  tenantId: string;
  actorId: string;
  domain: string;
  recordId: string;
  createdAt: number;
  expiresAt: number;
  status: DnsDeletionStatus;
  authorized: boolean;
  authorizedBy?: string;
  authorizedAt?: number;
  approvalTokenHash?: string;
  approvalToken?: string;
  consumed?: boolean;
  consumedAt?: number;
  completedAt?: number;
}

const PENDING_DELETION_REQUESTS = new Map<string, PendingDeletionRequest>();
const CONSUMED_APPROVAL_TOKENS = new Set<string>();

export interface DnsStatePayload {
  version: 1;
  requests: PendingDeletionRequest[];
  consumedTokenHashes: string[];
}

export function validateDnsStatePayload(data: unknown): DnsStatePayload {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Invalid state file: root must be an object');
  }
  const obj = data as Record<string, unknown>;
  if (obj.version !== 1) {
    throw new Error(`Invalid state file: unsupported version '${obj.version}', expected 1`);
  }
  if (!Array.isArray(obj.requests)) {
    throw new Error('Invalid state file: requests must be an array');
  }
  if (!Array.isArray(obj.consumedTokenHashes)) {
    throw new Error('Invalid state file: consumedTokenHashes must be an array');
  }

  const validRequests: PendingDeletionRequest[] = [];
  for (const item of obj.requests) {
    if (typeof item !== 'object' || item === null) {
      throw new Error('Invalid state file: request entry must be an object');
    }
    const r = item as Record<string, unknown>;
    if (
      typeof r.requestId !== 'string' ||
      typeof r.tenantId !== 'string' ||
      typeof r.actorId !== 'string' ||
      typeof r.domain !== 'string' ||
      typeof r.recordId !== 'string' ||
      typeof r.createdAt !== 'number' ||
      typeof r.expiresAt !== 'number'
    ) {
      throw new Error(`Invalid state file: missing or invalid required fields in request ${r.requestId || 'unknown'}`);
    }
    validRequests.push({
      requestId: r.requestId,
      tenantId: r.tenantId,
      actorId: r.actorId,
      domain: r.domain,
      recordId: r.recordId,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
      status: (r.status as DnsDeletionStatus) || (r.consumed ? 'completed' : r.authorized ? 'approved' : 'pending'),
      authorized: Boolean(r.authorized),
      authorizedBy: typeof r.authorizedBy === 'string' ? r.authorizedBy : undefined,
      authorizedAt: typeof r.authorizedAt === 'number' ? r.authorizedAt : undefined,
      approvalTokenHash: typeof r.approvalTokenHash === 'string' ? r.approvalTokenHash : undefined,
      approvalToken: typeof r.approvalToken === 'string' ? r.approvalToken : undefined,
      consumed: Boolean(r.consumed),
      consumedAt: typeof r.consumedAt === 'number' ? r.consumedAt : undefined,
      completedAt: typeof r.completedAt === 'number' ? r.completedAt : undefined
    });
  }

  const validHashes: string[] = [];
  for (const h of obj.consumedTokenHashes) {
    if (typeof h !== 'string' || h.length !== 64) {
      throw new Error(`Invalid state file: consumedTokenHash must be a 64-char SHA-256 hex string, got '${h}'`);
    }
    validHashes.push(h);
  }

  return {
    version: 1,
    requests: validRequests,
    consumedTokenHashes: validHashes
  };
}

function getDnsStateFilePath(): string {
  const dir = ensureStorageDir();
  return path.join(dir, 'dns-deletion-state.json');
}

function loadDnsStateFromDisk(): void {
  const dir = ensureStorageDir();
  const stateFile = getDnsStateFilePath();
  const legacyReqFile = path.join(dir, 'dns-deletion-requests.json');
  const legacyConsumedFile = path.join(dir, 'dns-consumed-tokens.json');

  // Multi-process hygiene: Clear in-memory collections before loading fresh authoritative state
  PENDING_DELETION_REQUESTS.clear();
  CONSUMED_APPROVAL_TOKENS.clear();

  if (fs.existsSync(stateFile)) {
    try {
      const content = fs.readFileSync(stateFile, 'utf-8');
      const raw = JSON.parse(content);
      const data = validateDnsStatePayload(raw);
      const now = Date.now();
      for (const item of data.requests) {
        if (item.requestId && item.expiresAt > now && item.status !== 'completed' && item.status !== 'failed') {
          PENDING_DELETION_REQUESTS.set(item.requestId, item);
        }
      }
      for (const hash of data.consumedTokenHashes) {
        CONSUMED_APPROVAL_TOKENS.add(hash);
      }
      return;
    } catch (err) {
      if (isHardenedEnvironment()) {
        throw new Error(`CRITICAL: Security state file '${stateFile}' failed validation or reading: ${err instanceof Error ? err.message : String(err)}`);
      }
      process.stderr.write(`[aeitron-mcp][WARN] Failed to parse/validate state file '${stateFile}': ${err instanceof Error ? err.message : String(err)}\n`);
    }
  }

  // Backward compatibility with legacy separate files if unified state file is not yet initialized
  if (fs.existsSync(legacyReqFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(legacyReqFile, 'utf-8'));
      if (Array.isArray(data)) {
        const now = Date.now();
        for (const item of data) {
          if (item.requestId && item.expiresAt > now && !item.consumed) {
            PENDING_DELETION_REQUESTS.set(item.requestId, {
              ...item,
              status: item.authorized ? 'approved' : 'pending'
            });
          }
        }
      }
    } catch (err) {
      if (isHardenedEnvironment()) {
        throw new Error(`CRITICAL: Unable to read security state file '${legacyReqFile}': ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  if (fs.existsSync(legacyConsumedFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(legacyConsumedFile, 'utf-8'));
      if (Array.isArray(data)) {
        for (const hash of data) {
          if (typeof hash === 'string') {
            CONSUMED_APPROVAL_TOKENS.add(hash);
          }
        }
      }
    } catch (err) {
      if (isHardenedEnvironment()) {
        throw new Error(`CRITICAL: Unable to read security state file '${legacyConsumedFile}': ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }
}

function saveDnsStateToDisk(): void {
  const stateFile = getDnsStateFilePath();
  try {
    const payload: DnsStatePayload = {
      version: 1,
      requests: Array.from(PENDING_DELETION_REQUESTS.values()).map((r) => ({
        ...r,
        // Redact plaintext token so sensitive credentials are never stored on disk
        approvalToken: undefined
      })),
      consumedTokenHashes: Array.from(CONSUMED_APPROVAL_TOKENS)
    };
    const tempStateFile = `${stateFile}.tmp.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`;
    fs.writeFileSync(tempStateFile, JSON.stringify(payload, null, 2), { encoding: 'utf-8', mode: 0o600 });
    fs.renameSync(tempStateFile, stateFile);
  } catch (err) {
    if (isHardenedEnvironment()) {
      throw new Error(`CRITICAL: Failed to persist unified DNS deletion state to '${stateFile}' in hardened environment: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}

// Initial state load
loadDnsStateFromDisk();

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
  PENDING_DELETION_REQUESTS.clear();
  CONSUMED_APPROVAL_TOKENS.clear();
  try {
    const stateFile = getDnsStateFilePath();
    if (fs.existsSync(stateFile)) fs.unlinkSync(stateFile);
  } catch {
    // Ignore cleanup errors in tests
  }
}

/**
 * Retrieves a pending DNS deletion request by ID (verifying TTL)
 */
export function getPendingDnsDeletionRequest(requestId: string): PendingDeletionRequest | undefined {
  return withDnsStateLock(() => {
    loadDnsStateFromDisk();
    const req = PENDING_DELETION_REQUESTS.get(requestId);
    if (req && Date.now() > req.expiresAt) {
      PENDING_DELETION_REQUESTS.delete(requestId);
      saveDnsStateToDisk();
      return undefined;
    }
    return req;
  });
}

/**
 * Lists pending DNS deletion requests, strictly filtered by tenant ID.
 * Fail-Closed: anonymous or missing tenant cannot enumerate requests across all tenants.
 */
export function listPendingDnsDeletionRequests(tenantId?: string): PendingDeletionRequest[] {
  return withDnsStateLock(() => {
    loadDnsStateFromDisk();
    if (!tenantId || tenantId === 'anonymous') {
      return [];
    }
    const now = Date.now();
    const results: PendingDeletionRequest[] = [];
    for (const req of PENDING_DELETION_REQUESTS.values()) {
      if (req.expiresAt > now && !req.consumed && req.status === 'pending') {
        if (req.tenantId === tenantId) {
          results.push(req);
        }
      }
    }
    return results;
  });
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
  const isHardened = config.environment === 'production' || config.environment === 'staging';
  // Test fixture credentials are strictly prohibited in hardened environments (staging & production)
  if (!isHardened && clientId === 'aeitron_test_client_id' && clientSecret === 'secret_test_key_889') {
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
  req: IncomingMessage | Request | { headers: Record<string, string | string[] | undefined> | Headers },
  parsedUrl: URL
): { token?: string; wasInQuery: boolean } {
  // 1. Check Authorization header (Strongly preferred)
  let authHeader: string | undefined;
  if ('headers' in req && req.headers) {
    if (typeof (req.headers as Headers)?.get === 'function') {
      authHeader = (req.headers as Headers).get('authorization') || undefined;
    } else if (typeof req.headers === 'object') {
      const h = (req.headers as Record<string, string | string[] | undefined>)['authorization'];
      authHeader = Array.isArray(h) ? h[0] : h;
    }
  }

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
    const isHardened = isProd || config.environment === 'staging';
    if (isHardened || !allowSandbox) {
      return {
        success: false,
        status: 401,
        code: isProd ? 'SANDBOX_DISABLED_IN_PROD' : 'SANDBOX_DISABLED_IN_HARDENED_ENV',
        error: `Sandbox credentials are not permitted in ${config.environment} environments.`
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
  // 2. JWT Cryptographic Verification (RS256 & HMAC-SHA256)
  // --------------------------------------------------------------------------
  if (token.startsWith('eyJ') && token.split('.').length === 3) {
    const [headerB64, payloadB64, sigB64] = token.split('.');

    try {
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8')) as Record<string, unknown>;
      const content = `${headerB64}.${payloadB64}`;

      if (header.alg === 'RS256') {
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(content);

        let valid = false;
        const kid = typeof header.kid === 'string' ? header.kid : undefined;
        if (kid && REGISTERED_PUBLIC_KEYS.has(kid)) {
          const keyMeta = REGISTERED_PUBLIC_KEYS.get(kid)!;
          valid = verifier.verify(keyMeta.publicKeyPem, sigB64, 'base64url');
        } else {
          valid = verifier.verify(RSA_KEY_PAIR.publicKey, sigB64, 'base64url');
          if (!valid) {
            for (const keyMeta of REGISTERED_PUBLIC_KEYS.values()) {
              const retryVerifier = crypto.createVerify('RSA-SHA256');
              retryVerifier.update(content);
              if (retryVerifier.verify(keyMeta.publicKeyPem, sigB64, 'base64url')) {
                valid = true;
                break;
              }
            }
          }
        }

        if (!valid) {
          return {
            success: false,
            status: 401,
            code: 'INVALID_SIGNATURE',
            error: 'Cryptographic RS256 JWT signature verification failed against public key.'
          };
        }
      } else if (header.alg === 'HS256') {
        const expectedSig = crypto
          .createHmac('sha256', jwtSecret)
          .update(content)
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
      } else {
        return {
          success: false,
          status: 401,
          code: 'UNSUPPORTED_ALGORITHM',
          error: `Unsupported signing algorithm '${header.alg}'. Accepted algorithms: RS256, HS256.`
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

      // H. Mandatory Actor Identity Check (P1: sub or actor_id must be present and non-empty)
      const rawActorId = (typeof payload.sub === 'string' && payload.sub.trim()) ||
                         (typeof payload.actor_id === 'string' && payload.actor_id.trim());
      if (!rawActorId) {
        return {
          success: false,
          status: 401,
          code: 'MISSING_ACTOR_CLAIM',
          error: 'JWT is missing mandatory actor claim ("sub" or "actor_id"). Synthetic identities are prohibited.'
        };
      }

      // I. Mandatory Tenant Identity Check (P1: tenant_id or org_id must be present and non-empty)
      const rawTenantId = (typeof payload.tenant_id === 'string' && payload.tenant_id.trim()) ||
                          (typeof payload.org_id === 'string' && payload.org_id.trim());
      if (!rawTenantId) {
        return {
          success: false,
          status: 401,
          code: 'MISSING_TENANT_CLAIM',
          error: 'JWT is missing mandatory tenant claim ("tenant_id" or "org_id"). Synthetic identities are prohibited.'
        };
      }

      // J. Strict Scope Format Validation
      if (!Array.isArray(scopes) || !scopes.every((s) => typeof s === 'string' && s.trim().length > 0)) {
        return {
          success: false,
          status: 401,
          code: 'INVALID_SCOPES_CLAIM',
          error: 'JWT scopes must be an array of non-empty strings.'
        };
      }

      const claims: AuthClaims = {
        actorId: rawActorId,
        tenantId: rawTenantId,
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
 * Creates a pending deletion request requiring human operator authorization.
 * AI models are strictly prohibited from self-authorizing destructive actions.
 */
export function createDnsDeletionRequest(
  tenantId: string,
  actorId: string,
  domain: string,
  recordId: string
): { requestId: string; expiresAt: number } {
  return withDnsStateLock(() => {
    loadDnsStateFromDisk();
    const requestId = `del_req_${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minute validity window

    const record: PendingDeletionRequest = {
      requestId,
      tenantId,
      actorId,
      domain,
      recordId,
      createdAt: Date.now(),
      expiresAt,
      status: 'pending',
      authorized: false
    };

    PENDING_DELETION_REQUESTS.set(requestId, record);
    saveDnsStateToDisk();

    return { requestId, expiresAt };
  });
}

/**
 * Authorizes a pending deletion request by a verified human operator and issues a single-use token.
 */
export const DNS_APPROVAL_SCOPE = 'dns:delete:approve';

/**
 * Authorizes a pending deletion request by a verified human operator and issues a single-use token.
 * Enforces independent dual-control: Request creators are strictly prohibited from approving their own requests.
 */
export function authorizeDnsDeletionRequest(
  operatorClaims: AuthClaims,
  requestId: string,
  secret?: string
): {
  success: true;
  token: string;
  expiresAt: number;
  requestId: string;
  domain: string;
  recordId: string;
} | {
  success: false;
  error: string;
  status: number;
} {
  // 1. Mandatory dedicated operator scope check (Wildcards & standard write scopes strictly disallowed)
  if (!operatorClaims.scopes.includes(DNS_APPROVAL_SCOPE)) {
    return {
      success: false,
      status: 403,
      error: `Operator lacks mandatory "${DNS_APPROVAL_SCOPE}" permission scope required to authorize deletion.`
    };
  }

  return withDnsStateLock(() => {
    loadDnsStateFromDisk();
    const req = PENDING_DELETION_REQUESTS.get(requestId);
    if (!req) {
      return { success: false, status: 404, error: 'Pending deletion request not found or expired.' };
    }

    // 2. Strict Independent Human Approval Guard: Creator cannot self-approve
    if (operatorClaims.actorId === req.actorId) {
      return {
        success: false,
        status: 403,
        error: 'Security Policy Violation: Request creators cannot approve their own DNS deletion requests. Independent human operator authorization required.'
      };
    }

    // 3. Request state checks (unexpired, not consumed, not already authorized)
    if (Date.now() > req.expiresAt) {
      PENDING_DELETION_REQUESTS.delete(requestId);
      saveDnsStateToDisk();
      return { success: false, status: 410, error: 'Pending deletion request has expired.' };
    }
    if (req.status === 'completed' || req.consumed) {
      return { success: false, status: 410, error: 'Pending deletion request has already been executed/consumed.' };
    }
    if (req.status === 'approved' || req.authorized) {
      return { success: false, status: 410, error: 'Pending deletion request has already been authorized.' };
    }

    // 4. Tenant isolation check (Zero 'anonymous' bypass allowed)
    if (!operatorClaims.tenantId || operatorClaims.tenantId === 'anonymous' || req.tenantId !== operatorClaims.tenantId) {
      return { success: false, status: 403, error: 'Operator tenant does not match deletion request tenant.' };
    }

    const challenge = createAuthorizedDnsDeletionToken(req.tenantId, req.domain, req.recordId, req.requestId, secret);
    const tokenHash = crypto.createHash('sha256').update(challenge.token).digest('hex');

    req.status = 'approved';
    req.authorized = true;
    req.authorizedBy = operatorClaims.actorId;
    req.authorizedAt = Date.now();
    req.approvalTokenHash = tokenHash;
    req.approvalToken = challenge.token;
    saveDnsStateToDisk();

    return {
      success: true,
      token: challenge.token,
      expiresAt: challenge.expiresAt,
      requestId: req.requestId,
      domain: req.domain,
      recordId: req.recordId
    };
  });
}

/**
 * Creates an authorized, cryptographically signed, one-time deletion token.
 */
export function createAuthorizedDnsDeletionToken(
  tenantId: string,
  domain: string,
  recordId: string,
  requestId: string,
  secret?: string
): { token: string; expiresAt: number; requestId: string } {
  if (!requestId) {
    throw new Error('Mandatory requestId required to issue an authorized deletion challenge token.');
  }
  const config = getConfig();
  const signingSecret = secret || config.jwtSecret;
  const expiresAt = Date.now() + 5 * 60 * 1000;
  const nonce = crypto.randomBytes(8).toString('hex');

  const payload = JSON.stringify({
    action: 'dns_delete_challenge',
    requestId,
    tenantId,
    domain,
    recordId,
    nonce,
    expiresAt
  });

  const payloadB64 = Buffer.from(payload).toString('base64url');
  const signature = crypto
    .createHmac('sha256', signingSecret)
    .update(`del:${payloadB64}`)
    .digest('base64url');

  return {
    token: `del_tok_${payloadB64}.${signature}`,
    expiresAt,
    requestId
  };
}

// Strictly for test suites to issue challenge tokens in non-hardened test environments
export function issueDnsDeletionChallenge(
  tenantId: string,
  domain: string,
  recordId: string,
  secret?: string
): { token: string; expiresAt: number; requestId: string } {
  if (isHardenedEnvironment()) {
    throw new Error('SECURITY VIOLATION: issueDnsDeletionChallenge is strictly prohibited in hardened environments.');
  }
  const req = createDnsDeletionRequest(tenantId, 'usr_requester_client', domain, recordId);
  const authorized = authorizeDnsDeletionRequest(
    {
      actorId: 'usr_independent_human_operator',
      tenantId,
      tier: 'enterprise',
      scopes: [DNS_APPROVAL_SCOPE],
      livemode: false
    },
    req.requestId,
    secret
  );
  if (!authorized.success) {
    throw new Error(`Failed to issue challenge token: ${authorized.error}`);
  }
  return {
    token: authorized.token,
    expiresAt: authorized.expiresAt,
    requestId: authorized.requestId
  };
}

/**
 * Verifies and atomically consumes a DNS deletion approval challenge token.
 * Enforces single-use replay protection and strict request binding.
 */
export function verifyAndConsumeDnsDeletionApproval(
  challengeToken: string,
  expectedTenantId: string,
  expectedDomain: string,
  expectedRecordId: string,
  secret?: string
): { valid: true; requestId: string } | { valid: false; error: string } {
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

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
  } catch {
    return { valid: false, error: 'Failed to decode challenge token payload.' };
  }

  if (payload.action !== 'dns_delete_challenge') {
    return { valid: false, error: 'Invalid challenge action payload.' };
  }
  if (typeof payload.expiresAt !== 'number' || Date.now() > payload.expiresAt) {
    return { valid: false, error: 'Challenge approval token has expired (5-minute TTL exceeded).' };
  }
  if (payload.domain !== expectedDomain || payload.recordId !== expectedRecordId) {
    return { valid: false, error: 'Challenge approval token does not match target domain or record ID.' };
  }
  if (!expectedTenantId || expectedTenantId === 'anonymous' || payload.tenantId !== expectedTenantId) {
    return { valid: false, error: 'Challenge approval token tenant mismatch.' };
  }

  // MANDATORY REQUEST ID ENFORCEMENT & DURABLE BINDING
  if (!payload.requestId || typeof payload.requestId !== 'string') {
    return {
      valid: false,
      error: 'Security Error: Approval token is missing mandatory requestId. Human operator authorization required.'
    };
  }

  const tokenHash = crypto.createHash('sha256').update(challengeToken).digest('hex');

  return withDnsStateLock(() => {
    loadDnsStateFromDisk();

    if (CONSUMED_APPROVAL_TOKENS.has(tokenHash)) {
      return { valid: false, error: 'Approval token has already been consumed (replay attempt detected).' };
    }

    const req = PENDING_DELETION_REQUESTS.get(payload.requestId as string);
    if (!req) {
      return {
        valid: false,
        error: `Referenced deletion request '${payload.requestId}' was not found or has expired.`
      };
    }
    if (!req.authorized || req.status === 'pending') {
      return {
        valid: false,
        error: `Referenced deletion request '${payload.requestId}' has not been authorized by an operator.`
      };
    }
    if (req.status === 'completed' || req.consumed) {
      return {
        valid: false,
        error: `Referenced deletion request '${payload.requestId}' has already been consumed (replay attempt detected).`
      };
    }
    if (Date.now() > req.expiresAt) {
      return {
        valid: false,
        error: `Referenced deletion request '${payload.requestId}' has expired.`
      };
    }
    if (req.approvalTokenHash && req.approvalTokenHash !== tokenHash) {
      return {
        valid: false,
        error: 'Challenge approval token does not match authorized token issued for this request.'
      };
    }
    if (req.approvalToken && req.approvalToken !== challengeToken) {
      return {
        valid: false,
        error: 'Challenge approval token does not match authorized token issued for this request.'
      };
    }
    if (req.domain !== expectedDomain || req.recordId !== expectedRecordId) {
      return {
        valid: false,
        error: 'Referenced deletion request parameters do not match target domain or record ID.'
      };
    }
    if (!expectedTenantId || expectedTenantId === 'anonymous' || req.tenantId !== expectedTenantId) {
      return {
        valid: false,
        error: 'Referenced deletion request tenant does not match caller tenant.'
      };
    }

    // Atomically transition state to 'executing' and record consumed token
    req.status = 'executing';
    req.consumed = true;
    req.consumedAt = Date.now();
    CONSUMED_APPROVAL_TOKENS.add(tokenHash);
    saveDnsStateToDisk();

    return { valid: true, requestId: req.requestId };
  });
}

/**
 * Transitions a DNS deletion request to completed status after successful upstream execution.
 */
export function markDnsDeletionCompleted(requestId: string): void {
  withDnsStateLock(() => {
    loadDnsStateFromDisk();
    const req = PENDING_DELETION_REQUESTS.get(requestId);
    if (req) {
      req.status = 'completed';
      req.completedAt = Date.now();
      saveDnsStateToDisk();
    }
  });
}

/**
 * Transitions a DNS deletion request to failed status if upstream execution failed.
 */
export function markDnsDeletionFailed(requestId: string): void {
  withDnsStateLock(() => {
    loadDnsStateFromDisk();
    const req = PENDING_DELETION_REQUESTS.get(requestId);
    if (req) {
      req.status = 'failed';
      saveDnsStateToDisk();
    }
  });
}

// Backwards-compatible alias
export const verifyDnsDeletionChallenge = verifyAndConsumeDnsDeletionApproval;

/**
 * Issues an RFC 7519 / RFC 7517 compliant OAuth 2.0 access token
 * signed with RS256 using the active RSA private key and kid.
 */
export function issueOAuthAccessToken(client: OAuthClient): string {
  return createSignedTestJwt(
    {
      sub: client.actorId,
      tenant_id: client.tenantId,
      scopes: client.scopes
    },
    { algorithm: 'RS256', kid: ACTIVE_KID }
  );
}

/**
 * Helper to generate cryptographically signed test JWTs for testing & OAuth flows.
 * Supports both standard symmetric HS256 and asymmetric RS256 signing.
 */
export function createSignedTestJwt(
  payload: Record<string, unknown>,
  options?: { secret?: string; algorithm?: 'HS256' | 'RS256'; kid?: string } | string
): string {
  const config = getConfig();
  let alg: 'HS256' | 'RS256' = 'RS256';
  let signingSecret: string = config.jwtSecret;
  let kid: string | undefined = ACTIVE_KID;

  if (typeof options === 'string') {
    if (options === 'RS256' || options === 'HS256') {
      alg = options;
      if (alg === 'HS256') kid = undefined;
    } else {
      alg = 'HS256';
      signingSecret = options;
      kid = undefined;
    }
  } else if (typeof options === 'object' && options !== null) {
    if (options.algorithm) {
      alg = options.algorithm;
    } else if (options.secret) {
      alg = 'HS256';
    }
    if (options.secret) {
      signingSecret = options.secret;
    }
    if (options.kid) {
      kid = options.kid;
    } else if (alg === 'HS256') {
      kid = undefined;
    }
  }

  const headerB64 = Buffer.from(JSON.stringify({
    alg,
    typ: 'JWT',
    kid: alg === 'RS256' ? (kid || ACTIVE_KID) : undefined
  })).toString('base64url');

  const defaultPayload: Record<string, unknown> = {
    iss: 'https://api.aeitron.com',
    aud: 'aeitron-mcp',
    exp: Math.floor(Date.now() / 1000) + 3600,
    scopes: ['account:read', 'projects:read', 'dns:read', 'usage:read']
  };

  if (!('sub' in payload) && !('actor_id' in payload)) {
    defaultPayload.sub = 'usr_test_client';
  }
  if (!('tenant_id' in payload) && !('org_id' in payload)) {
    defaultPayload.tenant_id = 'tenant_test_workspace';
  }

  const payloadB64 = Buffer.from(JSON.stringify({
    ...defaultPayload,
    ...payload
  })).toString('base64url');

  const content = `${headerB64}.${payloadB64}`;

  if (alg === 'RS256') {
    const signature = crypto
      .createSign('RSA-SHA256')
      .update(content)
      .sign(RSA_KEY_PAIR.privateKey, 'base64url');
    return `${content}.${signature}`;
  }

  const signature = crypto
    .createHmac('sha256', signingSecret)
    .update(content)
    .digest('base64url');

  return `${content}.${signature}`;
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
      'dns:delete:approve',
      'usage:read'
    ],
    response_types_supported: ['token'],
    grant_types_supported: ['client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    service_documentation: 'https://docs.aeitron.com/mcp'
  };
}

/**
 * Returns RFC 7517 compliant JSON Web Key Set (JWKS) metadata with real RSA public key
 */
export function getJwksMetadata(): { keys: Array<Record<string, unknown>> } {
  const keys: Array<Record<string, unknown>> = [];
  for (const [kid, entry] of REGISTERED_PUBLIC_KEYS.entries()) {
    keys.push({
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      kid,
      n: entry.jwk.n,
      e: entry.jwk.e
    });
  }
  return { keys };
}

/**
 * Public, safe DTO for DNS deletion requests.
 * Explicitly redacts approvalToken so sensitive tokens are NEVER leaked via read endpoints.
 */
export interface DnsDeletionRequestDto {
  requestId: string;
  tenantId: string;
  actorId: string;
  domain: string;
  recordId: string;
  createdAt: number;
  expiresAt: number;
  status: DnsDeletionStatus;
  authorized: boolean;
  authorizedBy?: string;
  authorizedAt?: number;
  consumed: boolean;
  consumedAt?: number;
  completedAt?: number;
}

export function toRedactedDnsRequestDto(req: PendingDeletionRequest): DnsDeletionRequestDto {
  return {
    requestId: req.requestId,
    tenantId: req.tenantId,
    actorId: req.actorId,
    domain: req.domain,
    recordId: req.recordId,
    createdAt: req.createdAt,
    expiresAt: req.expiresAt,
    status: req.status || (req.consumed ? 'completed' : req.authorized ? 'approved' : 'pending'),
    authorized: req.authorized,
    authorizedBy: req.authorizedBy,
    authorizedAt: req.authorizedAt,
    consumed: req.consumed || false,
    consumedAt: req.consumedAt,
    completedAt: req.completedAt
  };
}

export function resetDnsStateForTesting(): void {
  PENDING_DELETION_REQUESTS.clear();
  CONSUMED_APPROVAL_TOKENS.clear();
}
