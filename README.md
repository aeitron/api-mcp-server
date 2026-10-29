# Aeitron Model Context Protocol (MCP) Server

Official Model Context Protocol (MCP) server for the **Aeitron Cloud & Edge Infrastructure Platform**.

This service serves as a secure, sandboxed integration layer bridging LLM clients (such as Claude Desktop, Claude Web, ChatGPT, Cursor, and autonomous AI coding agents) with Aeitron's infrastructure APIs.

---

## Capabilities & Tools

[![Aeitron MCP Server CI](https://github.com/aeitron/mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/aeitron/mcp-server/actions/workflows/ci.yml)
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
| `delete_dns_record` | `dns:write:delete` | High-Risk Write | Permanently deletes a DNS record from the domain zone (Requires explicit `confirm: true` safety guard). |

---

## Security Architecture

- **Zero Direct Database Access:** The MCP server never connects to internal databases or executes shell commands. All operations are dispatched through the edge API Gateway.
- **Credential Redaction:** Sensitive tokens, passwords, private keys, and authorization headers are deeply sanitized before being logged or returned to the LLM context.
- **Tenant Isolation:** The tenant context is strictly extracted from server-validated Bearer credentials; clients cannot impersonate other tenants.
- **Audit Trails:** Structured single-line JSON logs are emitted for every tool invocation.

---

## Quickstart: Claude Desktop Integration

To connect Claude Desktop to your Aeitron Infrastructure platform, add the following entry to your `claude_desktop_config.json`:

### macOS / Linux:
```json
{
  "mcpServers": {
    "aeitron": {
      "command": "node",
      "args": ["/path/to/aeitron/apps/mcp-server/dist/cli.js"],
      "env": {
        "AEITRON_API_BASE_URL": "https://api.aeitron.com",
        "AEITRON_API_KEY": "atk_live_your_aeitron_api_key_here"
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
      "args": ["C:\\path\\to\\aeitron\\apps\\mcp-server\\dist\\cli.js"],
      "env": {
        "AEITRON_API_BASE_URL": "https://api.aeitron.com",
        "AEITRON_API_KEY": "atk_live_your_aeitron_api_key_here"
      }
    }
  }
}
```

---

## Remote Streamable HTTP (SSE) Deployment

For remote AI clients (Claude Web, ChatGPT Custom Actions / Connectors, and cloud agents):

### Start the Remote HTTP Server:
```bash
# Starts the server on port 3005 (or process.env.PORT)
npm run serve
```

### Endpoints:
- **SSE Handshake:** `GET /mcp/sse?token=<token>` (or `Authorization: Bearer <token>`)
- **JSON-RPC Messages:** `POST /mcp/messages?sessionId=<sessionId>`
- **Health Check:** `GET /health`
- **Readiness Probe:** `GET /ready`
- **OAuth 2.0 Discovery:** `GET /.well-known/oauth-authorization-server`

---

## Local Development & Testing

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run build

# Run full test suite (23 passing tests covering stdio, SSE, audit, and OAuth)
npm test
```

