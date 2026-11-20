import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, createHash } from 'node:crypto';
import ssh2 from 'ssh2';
const { Server, utils } = ssh2;
import { runSftpOperation } from '../build/ssh/sftp-operation.js';
import { ConnectionGate } from '../build/ssh/resource-limits.js';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';
import { createToolServer } from '../build/tool-server.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';

const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
const fingerprint = createHash('sha256').update(utils.parseKey(key).getPublicSSH()).digest('hex');

async function fixture() {
  const clients = new Set();
  let closedResolve;
  const closed = new Promise(resolve => { closedResolve = resolve; });
  let entered;
  const called = new Promise(resolve => { entered = resolve; });
  const ssh = new Server({ hostKeys: [key] }, client => {
    clients.add(client);
    client.on('error', () => {});
    client.on('close', () => { clients.delete(client); closedResolve(); });
    client.on('authentication', ctx => ctx.accept());
    client.on('ready', () => client.on('session', accept => {
      const session = accept();
      session.on('sftp', acceptSftp => {
        const sftp = acceptSftp();
        sftp.on('error', () => {});
        for (const event of ['STAT', 'RENAME', 'REMOVE', 'OPENDIR']) {
          sftp.on(event, () => entered(event)); // Deliberately leave the request unanswered.
        }
      });
    }));
  });
  await new Promise(resolve => ssh.listen(0, '127.0.0.1', resolve));
  const config = { host: '127.0.0.1', port: ssh.address().port, username: 'test', password: 'test', hostVerifier: () => true };
  return { config, called, closed, async close() {
    for (const client of clients) client.end();
    await new Promise(resolve => ssh.close(resolve));
  } };
}

async function openSftp(client) {
  return new Promise((resolve, reject) => client.sftp((error, channel) => error ? reject(error) : resolve(channel)));
}

for (const method of ['stat', 'rename', 'unlink', 'readdir']) {
  test('overall deadline closes SSH and releases its slot for stalled ' + method, { timeout: 10000 }, async () => {
    const f = await fixture();
    const gate = new ConnectionGate(1);
    try {
      const pending = runSftpOperation(f.config, gate, 1000, async client => {
        const sftp = await openSftp(client);
        return new Promise((resolve, reject) => {
          const callback = error => error ? reject(error) : resolve();
          if (method === 'rename') sftp.rename('/from', '/to', callback);
          else sftp[method]('/path', callback);
        });
      });
      await f.called;
      await assert.rejects(pending, /timed out/);
      await f.closed;
      assert.equal(gate.activeCount, 0);
      assert.equal(await runSftpOperation(f.config, gate, 1000, async () => 'next operation'), 'next operation');
      assert.equal(gate.activeCount, 0);
    } finally { await f.close(); }
  });
}

test('HTTP disconnect cancels a real stalled SFTP list and releases both gates', { timeout: 10000 }, async () => {
  const f = await fixture();
  const token = 'a'.repeat(48);
  const registry = { target: { host: f.config.host, port: f.config.port, user: 'test', password: 'test', hostKeySha256: fingerprint } };
  const policy = parseHttpAccessPolicy(JSON.stringify([{ id: 'test', token, targets: ['target'] }]), new Set(['target']));
  const previous = process.env.SSH_MCP_HTTP_MAX_REQUESTS;
  process.env.SSH_MCP_HTTP_MAX_REQUESTS = '1';
  let cancelled;
  const aborted = new Promise(resolve => { cancelled = resolve; });
  const handler = createStreamableHttpHandler((principal, signal) => {
    signal.addEventListener('abort', cancelled, { once: true });
    return createToolServer(registry, { principal, signal }, 'http');
  });
  const http = createAuthenticatedHttpServer(policy, handler);
  if (previous === undefined) delete process.env.SSH_MCP_HTTP_MAX_REQUESTS;
  else process.env.SSH_MCP_HTTP_MAX_REQUESTS = previous;
  const { port } = await listenLoopback(http, '127.0.0.1', 0);
  const controller = new AbortController();
  const url = 'http://127.0.0.1:' + port + '/mcp';
  const headers = { authorization: 'Bearer ' + token, 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  try {
    const pending = fetch(url, { method: 'POST', headers, signal: controller.signal,
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'sftp_list', arguments: { remotePath: '/' } } }) })
      .then(response => response.text()).catch(() => undefined);
    await f.called;
    controller.abort();
    await aborted;
    await pending;
    await f.closed;
    // Retry after the close event has propagated to the HTTP request boundary.
    const response = await fetch(url, { method: 'POST', headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) });
    assert.equal(response.status, 200);
    await response.text();
  } finally {
    controller.abort();
    http.closeAllConnections();
    await new Promise(resolve => http.close(resolve));
    await f.close();
  }
});
