import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';
import { createToolServer } from '../build/tool-server.js';

const registry = {
  alpha: { host: '127.0.0.1', user: 'tester', password: 'unused', hostKeySha256: 'a'.repeat(64) },
  beta: { host: '127.0.0.2', user: 'tester', password: 'unused', hostKeySha256: 'b'.repeat(64) },
};
const token = 'a'.repeat(48);
const policy = parseHttpAccessPolicy(JSON.stringify([{ id: 'alice', token, targets: ['alpha'] }]), new Set(Object.keys(registry)));

test('HTTP MCP exposes all shared SSH tools but rejects unauthorized target before connecting', async () => {
  const server = createAuthenticatedHttpServer(policy, createStreamableHttpHandler(principal => createToolServer(registry, { principal }, 'http')));
  const { port } = await listenLoopback(server, '127.0.0.1', 0);
  let nextId = 0;
  async function rpc(method, params = {}) {
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++nextId, method, params }),
    });
    assert.equal(response.status, 200);
    const body = await response.text();
    const payload = body.startsWith('event:') ? body.split('\n').find(line => line.startsWith('data: '))?.slice(6) : body;
    return JSON.parse(payload);
  }
  try {
    const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
    assert.equal(init.result.serverInfo.name, 'SSH MCP Server');
    const tools = await rpc('tools/list');
    assert.deepEqual(tools.result.tools.map(tool => tool.name).sort(), ['exec', 'sftp_download', 'sftp_list', 'sftp_upload']);
    const denied = await rpc('tools/call', { name: 'exec', arguments: { target: 'beta', command: 'printf must-not-run' } });
    assert.match(JSON.stringify(denied), /access denied|Internal error|Unexpected error/i);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
