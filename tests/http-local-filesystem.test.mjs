import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';
import { createToolServer } from '../build/tool-server.js';

const targets = {
  alpha: { host: '127.0.0.1', user: 'tester', password: 'unused', hostKeySha256: 'a'.repeat(64) },
};
const token = 'a'.repeat(48);
const policy = parseHttpAccessPolicy(JSON.stringify([{ id: 'alice', token, targets: ['alpha'] }]), new Set(['alpha']));

test('authorized HTTP principals cannot access server-local filesystem via SFTP tools', async () => {
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
    const raw = await response.text();
    const data = raw.startsWith('event:') ? raw.split('\n').find(line => line.startsWith('data: '))?.slice(6) : raw;
    return JSON.parse(data);
  }
  try {
    await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'filesystem-test', version: '1' } });
    for (const [name, args] of [
      ['sftp_upload', { target: 'alpha', localPath: '/etc/passwd', remotePath: '/tmp/sensitive' }],
      ['sftp_download', { target: 'alpha', remotePath: '/tmp/sensitive', localPath: '/tmp/sensitive' }],
    ]) {
      const result = await rpc('tools/call', { name, arguments: args });
      assert.match(JSON.stringify(result), /HTTP local file transfer is disabled/i, name);
    }
  } finally {
    await new Promise((resolve, reject) => http.close(error => error ? reject(error) : resolve()));
  }
});
