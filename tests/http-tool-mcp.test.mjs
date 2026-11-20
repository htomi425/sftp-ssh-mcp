import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
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

test('HTTP MCP exposes exec and sftp_list but rejects unauthorized target before connecting', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-http-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const key = join(dir, 'test-private-key');
  const targets = {
    alpha: { ...registry.alpha, password: undefined, key },
    beta: registry.beta,
  };
  const server = createAuthenticatedHttpServer(policy, createStreamableHttpHandler(principal => createToolServer(targets, { principal }, 'http')));
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
    assert.deepEqual(tools.result.tools.map(tool => tool.name).sort(), ['exec', 'sftp_list']);
    const denied = await rpc('tools/call', { name: 'exec', arguments: { target: 'beta', command: 'printf must-not-run' } });
    assert.match(JSON.stringify(denied), /access denied/i);

    const exec = { name: 'exec', arguments: { command: 'printf test' } };
    const list = { name: 'sftp_list', arguments: { remotePath: '/tmp' } };
    for (const tool of [exec, list]) {
      const missing = JSON.stringify(await rpc('tools/call', tool));
      assert.match(missing, /SSH private key is unavailable/);
      assert.doesNotMatch(missing, /test-private-key|ENOENT/);
    }

    await writeFile(key, 'invalid test key data', { mode: 0o600 });
    const failedExec = JSON.stringify(await rpc('tools/call', exec));
    assert.match(failedExec, /SSH command execution failed/);
    assert.doesNotMatch(failedExec, /parse privateKey|invalid test key data/);
    const failedList = JSON.stringify(await rpc('tools/call', list));
    assert.match(failedList, /SSH directory listing failed/);
    assert.doesNotMatch(failedList, /parse privateKey|invalid test key data/);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test('stdio MCP still exposes all four SSH tools', async () => {
  const server = createToolServer(registry, {}, 'stdio');
  const client = new Client({ name: 'test', version: '1' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  try {
    await client.connect(clientTransport);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map(tool => tool.name).sort(), ['exec', 'sftp_download', 'sftp_list', 'sftp_upload']);
  } finally {
    await client.close();
    await server.close();
  }
});
