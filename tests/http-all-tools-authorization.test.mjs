import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';
import { createToolServer } from '../build/tool-server.js';

const targets = {
  alpha: { host: '127.0.0.1', user: 'tester', password: 'unused', hostKeySha256: 'a'.repeat(64) },
  beta: { host: '127.0.0.2', user: 'tester', password: 'unused', hostKeySha256: 'b'.repeat(64) },
};
const token = 'a'.repeat(48);
const policy = parseHttpAccessPolicy(JSON.stringify([{ id: 'alice', token, targets: ['alpha'] }]), new Set(Object.keys(targets)));

test('all HTTP MCP tools reject targets outside the authenticated principal scope', async () => {
  const http = createAuthenticatedHttpServer(policy, createStreamableHttpHandler(principal => createToolServer(targets, { principal }, 'http')));
  const { port } = await listenLoopback(http, '127.0.0.1', 0);
  let id = 0;
  async function rpc(method, params) {
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, accept: 'application/json, text/event-stream', 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
    });
    assert.equal(response.status, 200);
    const text = await response.text();
    const data = text.startsWith('event:') ? text.split('\n').find(line => line.startsWith('data: '))?.slice(6) : text;
    return JSON.parse(data);
  }
  try {
    const initialized = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'authz-test', version: '1' } });
    assert.equal(initialized.result.serverInfo.name, 'SSH MCP Server');
    const tools = await rpc('tools/list', {});
    assert.deepEqual(tools.result.tools.map(x => x.name).sort(), ['exec', 'sftp_download', 'sftp_list', 'sftp_upload']);
    for (const [name, args] of [
      ['exec', { target: 'beta', command: 'echo must-not-run' }],
      ['sftp_list', { target: 'beta', remotePath: '/tmp' }],
      ['sftp_upload', { target: 'beta', localPath: '/tmp/absent', remotePath: '/tmp/absent' }],
      ['sftp_download', { target: 'beta', remotePath: '/tmp/absent', localPath: '/tmp/absent' }],
    ]) {
      const result = await rpc('tools/call', { name, arguments: args });
      assert.match(JSON.stringify(result), /access denied/i, name);
    }
  } finally {
    await new Promise((resolve, reject) => http.close(error => error ? reject(error) : resolve()));
  }
});
