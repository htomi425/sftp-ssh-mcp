import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Readable } from 'node:stream';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';

const token = 'a'.repeat(48);
const policy = parseHttpAccessPolicy(JSON.stringify([{ id: 'test', token, targets: ['alpha'] }]), new Set(['alpha']));

test('HTTP MCP rejects oversized chunked request with 413 before protocol handling', async () => {
  const oldLimit = process.env.SSH_MCP_HTTP_MAX_BODY_BYTES;
  process.env.SSH_MCP_HTTP_MAX_BODY_BYTES = '1024';
  const handler = createStreamableHttpHandler(() => new McpServer({ name: 'size-test', version: '1.0' }));
  const server = createAuthenticatedHttpServer(policy, handler);
  const { port } = await listenLoopback(server, '127.0.0.1', 0);
  try {
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: Readable.from([Buffer.from('{"data":"'), Buffer.alloc(2048, 97), Buffer.from('"}')]),
      duplex: 'half',
    });
    assert.equal(response.status, 413);

    const declaredOversize = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ data: 'x'.repeat(2048) }),
    });
    assert.equal(declaredOversize.status, 413);

    const invalidJson = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: '{',
    });
    assert.equal(invalidJson.status, 400);
  } finally {
    await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
    if (oldLimit === undefined) delete process.env.SSH_MCP_HTTP_MAX_BODY_BYTES;
    else process.env.SSH_MCP_HTTP_MAX_BODY_BYTES = oldLimit;
  }
});
