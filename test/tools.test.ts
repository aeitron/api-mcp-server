import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { createAeitronMcpServer } from '../src/server.js';
import { AuditLogger } from '../src/audit.js';
import { AuditRecord } from '../src/types.js';
import {
  issueDnsDeletionChallenge,
  authorizeDnsDeletionRequest,
  createSignedTestJwt,
  getPendingDnsDeletionRequest
} from '../src/auth.js';
import { handleDnsApproveDeletion } from '../src/cli.js';

describe('Aeitron MCP Tools Suite (Phase 1 & Phase 2 Security)', () => {
  let client: Client;
  let serverInstance: ReturnType<typeof createAeitronMcpServer>;
  const auditLogs: AuditRecord[] = [];

  before(async () => {
    const audit = new AuditLogger((record) => auditLogs.push(record));
    serverInstance = createAeitronMcpServer({
      audit,
      authClaims: {
        tenantId: 'tenant_customerAcme',
        actorId: 'usr_live_acme_admin',
        tier: 'enterprise',
        scopes: [
          'account:read',
          'projects:read',
          'projects:write',
          'dns:read',
          'dns:write',
          'dns:write:delete',
          'usage:read'
        ],
        livemode: true
      },
      config: {
        mockFallback: true,
        apiBaseUrl: 'http://127.0.0.1:9099'
      }
    });

    client = new Client({
      name: 'aeitron-test-client',
      version: '1.0.0'
    });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      serverInstance.server.connect(serverTransport),
      client.connect(clientTransport)
    ]);
  });

  after(async () => {
    await client.close();
    await serverInstance.server.close();
  });

  it('1. Tool Discovery: exposes all 5 Phase 1 tools via tools/list', async () => {
    const response = await client.listTools();
    const toolNames = response.tools.map((t) => t.name);

    assert.ok(toolNames.includes('get_account'), 'missing get_account');
    assert.ok(toolNames.includes('list_projects'), 'missing list_projects');
    assert.ok(toolNames.includes('get_project'), 'missing get_project');
    assert.ok(toolNames.includes('get_dns_records'), 'missing get_dns_records');
    assert.ok(toolNames.includes('get_usage'), 'missing get_usage');

    // Verify input schemas exist
    const dnsTool = response.tools.find((t) => t.name === 'get_dns_records');
    assert.ok(dnsTool?.inputSchema?.properties?.domain, 'get_dns_records must declare domain schema');
  });

  it('2. get_account: returns formatted account overview, tier, and resource quotas', async () => {
    const result = await client.callTool({
      name: 'get_account',
      arguments: {}
    });

    assert.equal(result.isError, undefined);
    assert.ok(Array.isArray(result.content));
    assert.ok(result.content.length >= 2);

    const markdownContent = (result.content[0] as { text: string }).text;
    const jsonContent = (result.content[1] as { text: string }).text;

    assert.ok(markdownContent.includes('### Aeitron Account Overview'));
    assert.ok(markdownContent.includes('developer@aeitron.internal'));
    assert.ok(markdownContent.includes('Quota & Resource Limits'));

    const parsed = JSON.parse(jsonContent);
    assert.equal(parsed.tier, 'developer');
    assert.equal(parsed.limits.maxProjects, 25);
    assert.equal(parsed.limits.maxDomains, 100);

    const log = auditLogs.find((l) => l.tool === 'get_account');
    assert.ok(log, 'Audit record for get_account must exist');
    assert.equal(log?.success, true);
  });

  it('3. list_projects: lists tenant projects with pagination', async () => {
    const result = await client.callTool({
      name: 'list_projects',
      arguments: { limit: 10, offset: 0 }
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    const markdown = content[0].text;
    const json = JSON.parse(content[1].text);

    assert.ok(markdown.includes('Projects Inventory'));
    assert.ok(markdown.includes('Production Edge Gateway'));
    assert.ok(json.projects.length > 0);
    assert.equal(json.projects[0].slug, 'prod-edge-gw');
  });

  it('4. get_project: retrieves detailed deployment status and hides sensitive env values', async () => {
    const result = await client.callTool({
      name: 'get_project',
      arguments: { projectId: 'prod-edge-gw' }
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    const markdown = content[0].text;
    const json = JSON.parse(content[1].text);

    assert.ok(markdown.includes('Project: Production Edge Gateway'));
    assert.ok(markdown.includes('Attached Domains'));
    assert.ok(markdown.includes('api.aeitron.com'));
    assert.ok(markdown.includes('24h Telemetry & Performance'));

    assert.ok(json.environmentVariables.includes('DATABASE_POOL_SIZE'));
    assert.ok(json.environmentVariables.includes('REDIS_CLUSTER_URL'));
    assert.ok(json.metrics.uptimePercentage > 99);
  });

  it('5. get_dns_records: retrieves zone records in clean tabular markdown', async () => {
    const result = await client.callTool({
      name: 'get_dns_records',
      arguments: { domain: 'aeitron.com' }
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    const markdown = content[0].text;
    const json = JSON.parse(content[1].text);

    assert.ok(markdown.includes('DNS Records for `aeitron.com`'));
    assert.ok(markdown.includes('| `A` |'));
    assert.ok(markdown.includes('| `AAAA` |'));
    assert.ok(markdown.includes('| `CNAME` |'));
    assert.ok(json.records.length >= 3);
  });

  it('6. Validation Safety: rejects invalid domain names in get_dns_records', async () => {
    const result = await client.callTool({
      name: 'get_dns_records',
      arguments: { domain: 'not-a-valid-domain' }
    });

    assert.equal(result.isError, true);
  });

  it('7. get_usage: returns infrastructure metrics and estimated billing totals', async () => {
    const result = await client.callTool({
      name: 'get_usage',
      arguments: { period: 'current' }
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    const markdown = content[0].text;
    const json = JSON.parse(content[1].text);

    assert.ok(markdown.includes('Aeitron Usage & Resource Consumption'));
    assert.ok(markdown.includes('Edge Requests:'));
    assert.ok(markdown.includes('Estimated Financials'));
    assert.ok(markdown.includes('Estimated Total:'));

    assert.equal(json.period, 'current');
    assert.equal(json.costs.currency, 'USD');
    assert.ok(json.costs.currentEstimatedTotal > 0);
  });

  it('8. create_project: provisions new project workspace', async () => {
    const result = await client.callTool({
      name: 'create_project',
      arguments: {
        name: 'AI Agent Ingress',
        region: 'global-anycast',
        framework: 'node-hono'
      }
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('Project Created Successfully'));
    const json = JSON.parse(content[1].text);
    assert.equal(json.name, 'AI Agent Ingress');
    assert.equal(json.slug, 'ai-agent-ingress');
  });

  it('9. create_dns_record: adds new DNS record with validation', async () => {
    const result = await client.callTool({
      name: 'create_dns_record',
      arguments: {
        domain: 'aeitron.com',
        type: 'A',
        name: 'staging',
        value: '198.51.100.55',
        ttl: 300,
        proxied: true
      }
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('DNS Record Created Successfully'));
    const json = JSON.parse(content[1].text);
    assert.equal(json.name, 'staging');
    assert.equal(json.type, 'A');
    assert.equal(json.value, '198.51.100.55');
  });

  it('10. delete_dns_record Challenge Guard: fails closed with operator challenge request ID when approvalToken is missing', async () => {
    const result = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_003',
        confirm: true // confirm without token must fail closed!
      }
    });

    assert.equal(result.isError, true);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('SAFETY GUARD'));
    assert.ok(content[0].text.includes('del_req_'));
  });

  it('11. delete_dns_record Dry Run: returns safe impact preview with deletion request ID without mutating DNS', async () => {
    const result = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_003',
        dryRun: true
      }
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('DRY RUN PREVIEW'));
    assert.ok(content[0].text.includes('rec_dns_cname_003'));
    assert.ok(content[0].text.includes('del_req_'));
  });

  it('12. delete_dns_record: executes permanent deletion when valid approvalToken and confirm are provided', async () => {
    const challenge = issueDnsDeletionChallenge('tenant_customerAcme', 'aeitron.com', 'rec_dns_cname_003');

    const result = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_003',
        confirm: true,
        approvalToken: challenge.token
      }
    });

    assert.equal(result.isError, undefined);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('DNS Record Deleted Successfully'));
    const json = JSON.parse(content[1].text);
    assert.equal(json.success, true);

    // Replaying the exact same token must immediately fail with replay detection
    const replayResult = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_003',
        confirm: true,
        approvalToken: challenge.token
      }
    });

    assert.equal(replayResult.isError, true);
    const replayContent = replayResult.content as Array<{ text: string }>;
    assert.ok(replayContent[0].text.includes('replay attempt detected'));
  });

  it('12b. End-to-End Human Operator Approval: dry run produces request ID, operator authorizes, deletion succeeds', async () => {
    // 1. Tool returns deletion request ID
    const dryRunResult = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_004',
        dryRun: true
      }
    });

    assert.equal(dryRunResult.isError, undefined);
    const dryRunText = (dryRunResult.content as Array<{ text: string }>)[0].text;
    const match = dryRunText.match(/del_req_[a-f0-9]+/);
    assert.ok(match, 'Must contain del_req_ request ID');
    const requestId = match[0];

    // 2. Operator authorizes request via authorizeDnsDeletionRequest
    const operatorApproval = authorizeDnsDeletionRequest(
      {
        actorId: 'usr_human_operator_42',
        tenantId: 'tenant_customerAcme',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: true
      },
      requestId
    );

    assert.equal(operatorApproval.success, true);
    if (!operatorApproval.success) return;
    assert.ok(operatorApproval.token.startsWith('del_tok_'));

    // 3. AI agent re-invokes deletion tool with the approval token
    const deleteResult = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_004',
        confirm: true,
        approvalToken: operatorApproval.token
      }
    });

    assert.equal(deleteResult.isError, undefined);
    const deleteContent = (deleteResult.content as Array<{ text: string }>)[0].text;
    assert.ok(deleteContent.includes('DNS Record Deleted Successfully'));

    // 4. Attempting to authorize or consume the same request again must fail
    const reApproval = authorizeDnsDeletionRequest(
      {
        actorId: 'usr_human_operator_42',
        tenantId: 'tenant_customerAcme',
        tier: 'enterprise',
        scopes: ['dns:delete:approve'],
        livemode: true
      },
      requestId
    );
    assert.equal(reApproval.success, false);
  });

  it('12c. CLI Operator Approval: authorizes request using handleDnsApproveDeletion CLI workflow', async () => {
    // 1. Tool triggers safety challenge
    const challengeResult = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_005',
        confirm: true
      }
    });

    assert.equal(challengeResult.isError, true);
    const challengeText = (challengeResult.content as Array<{ text: string }>)[0].text;
    const match = challengeText.match(/del_req_[a-f0-9]+/);
    assert.ok(match, 'Must contain del_req_ request ID');
    const requestId = match[0];

    // 2. Human operator runs CLI approval with operator token containing dns:delete:approve
    const operatorToken = createSignedTestJwt({
      sub: 'usr_operator_cli_admin',
      tenant_id: 'tenant_customerAcme',
      scopes: ['dns:delete:approve']
    });

    const cliResult = await handleDnsApproveDeletion({
      requestId,
      token: operatorToken
    });

    assert.equal(cliResult.success, true);
    assert.ok(cliResult.token && cliResult.token.startsWith('del_tok_'));

    // 3. Deletion succeeds with CLI-issued token
    const executionResult = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_005',
        confirm: true,
        approvalToken: cliResult.token
      }
    });

    assert.equal(executionResult.isError, undefined);
  });

  it('12d. delete_dns_record: preserves approvalToken when confirm is false or omitted', async () => {
    const challenge = issueDnsDeletionChallenge('tenant_customerAcme', 'aeitron.com', 'rec_dns_cname_006');

    // 1. Call with valid token but confirm: false -> fails but token is NOT consumed
    const unconfirmedResult = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_006',
        confirm: false,
        approvalToken: challenge.token
      }
    });

    assert.equal(unconfirmedResult.isError, true);
    const unconfirmedText = (unconfirmedResult.content as Array<{ text: string }>)[0].text;
    assert.ok(unconfirmedText.includes('SAFETY GUARD'));

    // 2. Call again with confirm: true using the SAME token -> succeeds!
    const confirmedResult = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_006',
        confirm: true,
        approvalToken: challenge.token
      }
    });

    assert.equal(confirmedResult.isError, undefined);
    const confirmedText = (confirmedResult.content as Array<{ text: string }>)[0].text;
    assert.ok(confirmedText.includes('DNS Record Deleted Successfully'));
  });

  it('12e. CLI Operator Approval: refuses local fallback when --url is specified and fails', async () => {
    const operatorToken = createSignedTestJwt({
      sub: 'usr_operator_cli_admin',
      tenant_id: 'tenant_customerAcme',
      scopes: ['dns:delete:approve']
    });

    const cliResult = await handleDnsApproveDeletion({
      requestId: 'del_req_mock_fail_test',
      token: operatorToken,
      url: 'http://127.0.0.1:59999' // Non-existent remote server
    });

    assert.equal(cliResult.success, false);
    assert.ok(cliResult.error?.includes('Remote approval failed'));
  });

  it('13. delete_dns_record: rejects invalid or forged approvalToken with 403 Forbidden', async () => {
    const result = await client.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_dns_cname_003',
        confirm: true,
        approvalToken: 'del_tok_forged_payload.bad_sig'
      }
    });

    assert.equal(result.isError, true);
    const content = result.content as Array<{ text: string }>;
    assert.ok(content[0].text.includes('403 Forbidden'));
  });

  it('14. Scope Enforcement Gate: denies tools when caller lacks required permission scope', async () => {
    const readOnlyServer = createAeitronMcpServer({
      authClaims: {
        tenantId: 'tenant_readonly',
        actorId: 'usr_readonly',
        tier: 'developer',
        scopes: ['account:read', 'projects:read', 'dns:read'],
        livemode: true
      },
      config: { mockFallback: true }
    });

    const limitedClient = new Client({ name: 'limited-client', version: '1.0.0' });
    const [cTransport, sTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      readOnlyServer.server.connect(sTransport),
      limitedClient.connect(cTransport)
    ]);

    const result = await limitedClient.callTool({
      name: 'delete_dns_record',
      arguments: { domain: 'aeitron.com', recordId: 'rec_01', confirm: true }
    });

    assert.equal(result.isError, true);
    const text = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(text.includes('403 Forbidden'));
    assert.ok(text.includes('dns:write:delete'));

    await limitedClient.close();
    await readOnlyServer.server.close();
  });

  it('15. delete_dns_record: upstream timeout marks request as execution_unknown and provides operator guidance', async () => {
    const timingOutClient = {
      deleteDnsRecord: async () => {
        const err = new Error('Request timed out after 5000ms');
        err.name = 'AbortError';
        throw err;
      }
    } as any;

    const timeoutServer = createAeitronMcpServer({
      client: timingOutClient,
      authClaims: {
        tenantId: 'tenant_customerAcme',
        actorId: 'usr_live_acme_admin',
        tier: 'enterprise',
        scopes: ['dns:write:delete'],
        livemode: true
      }
    });

    const timeoutMcpClient = new Client({ name: 'timeout-client', version: '1.0.0' });
    const [cTransport, sTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      timeoutServer.server.connect(sTransport),
      timeoutMcpClient.connect(cTransport)
    ]);

    const challenge = issueDnsDeletionChallenge('tenant_customerAcme', 'aeitron.com', 'rec_timeout_record_1');

    const result = await timeoutMcpClient.callTool({
      name: 'delete_dns_record',
      arguments: {
        domain: 'aeitron.com',
        recordId: 'rec_timeout_record_1',
        confirm: true,
        approvalToken: challenge.token
      }
    });

    assert.equal(result.isError, true);
    const content = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(content.includes('UPSTREAM TIMEOUT'));
    assert.ok(content.includes('execution_unknown'));
    assert.ok(content.includes('reconcile'));

    // Verify request in state is indeed execution_unknown
    const stateReq = getPendingDnsDeletionRequest(challenge.requestId);
    assert.ok(stateReq);
    assert.equal(stateReq.status, 'execution_unknown');

    await timeoutMcpClient.close();
    await timeoutServer.server.close();
  });
});
