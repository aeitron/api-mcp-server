# Aeitron Model Context Protocol (MCP) Server

Official Model Context Protocol (MCP) server for the **Aeitron Cloud & Edge Infrastructure Platform**.

This service serves as a secure, sandboxed integration layer bridging LLM clients (such as Claude Desktop, Claude Web, ChatGPT, Cursor, and autonomous AI coding agents) with Aeitron's infrastructure APIs.

---

## Capabilities & Tools

[![Aeitron MCP Server CI](https://github.com/aeitron/api-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/aeitron/api-mcp-server/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

The MCP server exposes strictly-typed, schema-validated tools governed by server-side authorization:

| Tool Name | Scope Required | Type | Description |
|---|---|---|---|
| `get_account` | `account:read` | Read | Returns authenticated user profile, organization, subscription tier, and global resource quotas. |
| `list_projects` | `projects:read` | Read | Lists all projects owned by or accessible to the tenant with pagination support. |
| `get_project` | `projects:read` | Read | Retrieves detailed deployment status, attached custom domains, and 24h edge telemetry for a specific project. |
| `get_dns_records` | `dns:read` | Read | Fetches active DNS records (A, AAAA, CNAME, TXT, MX) for an authorized domain on the Aeitron edge network. |
| `get_usage` | `usage:read` | Read | Summarizes bandwidth, edge request counts, microVM compute hours, and estimated billing costs. |
| `create_project` | `projects:write` | Write | Provisions a new project workspace on the Aeitron edge network. |
| `create_dns_record` | `dns:write` | Write | Adds a new DNS routing record to an authorized domain zone. |
| `delete_dns_record` | `dns:write:delete` | High-Risk Write | Permanently deletes a DNS record. Requires scope `dns:write:delete`, explicit `confirm: true`, and server-issued cryptographic `approvalToken`. |

---

## Security Architecture

- **Zero Hardcoded Credentials:** Zero live API keys in source code. Production credentials are dynamically loaded from `AEITRON_API_KEYS` and verified via SHA-256 hashes.
- **Fail-Closed Mandatory JWT Claims:** All JWTs must include valid numeric `exp` (expiration), trusted `iss` (`https://api.aeitron.com`), verified `aud` (`aeitron-mcp`), and explicit `scopes`. Missing claims or signatures reject with 401 Unauthorized.
- **Authenticated OAuth Token Exchange:** `POST /v1/auth/token` enforces real client authentication (client ID and client secret verification) before issuing scoped Bearer tokens.
- **Two-Step Destructive Action Challenge & Human MFA Verification:** Deleting DNS records cannot be self-authorized by an LLM prompt or machine service token. Destructive mutations require explicit human operator authorization (`dns:delete:approve` scope, `actor_type: 'human'`, and recent MFA within 5 minutes) via console or CLI (`aeitron dns approve-deletion`), issuing a short-lived, replay-protected cryptographic approval token (`del_tok_...`).
- **Authentic Socket-Level Rate Limiting:** Sensitive endpoints (`/v1/auth/token`, `/v1/dns/approve-deletion`, and DNS deletions) enforce rate limits bound to the underlying TCP socket remote address and tenant identity, blocking spoofed `X-Forwarded-For` bypasses and auto-pruning idle buckets.
- **Durable In-Flight Recovery & Expired Hash Pruning:** In-flight operations in `executing` and `execution_unknown` states remain durably retained across server restarts regardless of approval TTL, while consumed token hashes are automatically pruned once their retention window expires.
- **Modern Streamable HTTP & Legacy SSE:** Implements modern MCP Streamable HTTP (`POST /mcp`) alongside backward-compatible Server-Sent Events (`GET /mcp/sse`), complete with OPTIONS preflight handling and strict CORS origin allowlists.
- **Fail-Closed Tool Authorization:** Any unmapped tool or caller lacking explicit RBAC scopes is denied with 403 Forbidden.
- **Zero Direct Database Access:** Dispatches all operations through authorized upstream APIs.
- **Deep Redaction:** Sensitive tokens, keys, and authorization headers are recursively sanitized from audit logs.

---

## Quickstart: Claude Desktop Integration (STDIO)

To connect Claude Desktop to your Aeitron Infrastructure platform, configure `claude_desktop_config.json`:

### macOS / Linux:
```json
{
  "mcpServers": {
    "aeitron": {
      "command": "node",
      "args": ["/path/to/aeitron/apps/mcp-server/dist/src/cli.js"],
      "env": {
        "AEITRON_API_BASE_URL": "https://api.aeitron.com",
        "AEITRON_API_KEY": "your_authoritative_aeitron_api_key_here"
      }
    }
  }
}
```

### Windows:
```json
{
  "mcpServers": {
    "aeitron": {
      "command": "node",
      "args": ["C:\\path\\to\\aeitron\\apps\\mcp-server\\dist\\src\\cli.js"],
      "env": {
        "AEITRON_API_BASE_URL": "https://api.aeitron.com",
        "AEITRON_API_KEY": "your_authoritative_aeitron_api_key_here"
      }
    }
  }
}
```

---

## Remote Streamable HTTP & SSE Deployment

For remote AI clients (Claude Web, ChatGPT Custom Connectors, Cursor):

### Start the Remote Server:
```bash
npm run serve
```

### Endpoints:
- **Streamable HTTP (Modern MCP):** `POST /mcp`
- **SSE Handshake (Legacy MCP):** `GET /mcp/sse` (Headers: `Authorization: Bearer <token>`)
- **JSON-RPC Messages:** `POST /mcp/messages?sessionId=<sessionId>`
- **Health Check:** `GET /health`
- **Readiness Probe:** `GET /ready`
- **OAuth 2.0 Discovery:** `GET /.well-known/oauth-authorization-server`
- **JWKS Key Set:** `GET /.well-known/jwks.json`

---

## Local Development & Testing

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run build

# Run complete verification test suite (120 tests across 6 test suites)
npm test
```
