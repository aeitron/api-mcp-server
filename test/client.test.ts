import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AeitronApiClient, AeitronApiError } from '../src/client.js';

describe('Aeitron API Client Timeout & Lifecycle Suite', () => {
  it('aborts and throws 503 timeout error when response body read stalls beyond requestTimeoutMs', async () => {
    // Spin up an HTTP server that immediately sends 200 OK headers, but never finishes sending the body
    const server = http.createServer((req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Transfer-Encoding': 'chunked'
      });
      res.write('{"partial":');
      // Do not end the response; simulate stalled/slow body stream
    });

    let port = 0;
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        port = typeof addr === 'object' && addr !== null ? addr.port : 0;
        resolve();
      });
    });

    try {
      const client = new AeitronApiClient({
        apiBaseUrl: `http://127.0.0.1:${port}`,
        defaultApiKey: 'atk_test_timeout_key',
        requestTimeoutMs: 150, // Short timeout for test speed
        mockFallback: false
      });

      await assert.rejects(
        async () => {
          await client.getAccount();
        },
        (err: unknown) => {
          assert.ok(err instanceof AeitronApiError);
          assert.equal(err.status, 503);
          assert.equal(err.code, 'SERVICE_UNAVAILABLE');
          assert.ok(err.message.includes('timed out after 150ms'));
          return true;
        }
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('successfully parses response when completed within requestTimeoutMs', async () => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        id: 'acc_test_1',
        name: 'Fast Test Account',
        tier: 'enterprise',
        quotas: {
          edgeBandwidthBytes: 1000,
          usedBandwidthBytes: 100,
          dnsQueriesAllowed: 1000,
          dnsQueriesUsed: 10,
          customDomainsAllowed: 10,
          customDomainsUsed: 1
        }
      }));
    });

    let port = 0;
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        port = typeof addr === 'object' && addr !== null ? addr.port : 0;
        resolve();
      });
    });

    try {
      const client = new AeitronApiClient({
        apiBaseUrl: `http://127.0.0.1:${port}`,
        defaultApiKey: 'atk_test_fast_key',
        requestTimeoutMs: 1000,
        mockFallback: false
      });

      const account = await client.getAccount();
      assert.equal(account.id, 'acc_test_1');
      assert.equal(account.name, 'Fast Test Account');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
