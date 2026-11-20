import assert from 'node:assert/strict';
import { test } from 'node:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';

const token = 'a'.repeat(48);
const policy = parseHttpAccessPolicy(JSON.stringify([
  { id: 'tester', token, targets: ['alpha'] },
]), new Set(['alpha']));

test('real MCP initialize request over authenticated Streamable HTTP', async () => {
  const handler = createStreamableHttpHandler(principal => {
    const server = new McpServer({ name: 'test-http', version: '1.0.0' });
    server.tool('identity', 'Return authenticated principal', {}, async () => ({
      content: [{ type: 'text', text: principal.id }],
    }));
    return server;
  });
  const http = createAuthenticatedHttpServer(policy, handler);
  const { port } = await listenLoopback(http, '127.0.0.1', 0);
  try {
    const url = `http://127.0.0.1:${port}/mcp`;
    const body = JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'integration-test', version: '1.0' } },
    });
    const unauthorized = await fetch(url, {
      method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body,
    });
    assert.equal(unauthorized.status, 401);
    const authorized = await fetch(url, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body,
    });
    assert.equal(authorized.status, 200);
    const response = await authorized.text();
    assert.match(response, /test-http/);
    assert.match(response, /protocolVersion/);
  } finally {
    await new Promise((resolve, reject) => http.close(err => err ? reject(err) : resolve()));
  }
});
