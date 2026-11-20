import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';

const token = 'a'.repeat(48);
const policy = parseHttpAccessPolicy(JSON.stringify([{ id: 'tester', token, targets: ['alpha'] }]), new Set(['alpha']));

test('HTTP boundary rejects unauthenticated requests and isolates principal', async () => {
  const seen = [];
  const server = createAuthenticatedHttpServer(policy, async ({ principal, response }) => {
    seen.push(principal.id);
    policy.authorize(principal, 'alpha');
    response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }));
  });
  const { port } = await listenLoopback(server, '127.0.0.1', 0);
  try {
    const url = `http://127.0.0.1:${port}/mcp`;
    const missing = await fetch(url, { method: 'POST' });
    assert.equal(missing.status, 401);
    assert.equal(missing.headers.get('www-authenticate'), 'Bearer');
    const invalid = await fetch(url, { method: 'POST', headers: { authorization: 'Bearer ' + 'b'.repeat(48) } });
    assert.equal(invalid.status, 401);
    const crossOrigin = await fetch(url, { method: 'POST', headers: { authorization: 'Bearer ' + token, origin: 'https://untrusted.example' } });
    assert.equal(crossOrigin.status, 403);
    const good = await fetch(url, { method: 'POST', headers: { authorization: 'Bearer ' + token } });
    assert.equal(good.status, 200);
    assert.deepEqual(await good.json(), { ok: true });
    assert.deepEqual(seen, ['tester']);
    const wrongPath = await fetch(url.replace('/mcp', '/other'), { method: 'POST', headers: { authorization: 'Bearer ' + token } });
    assert.equal(wrongPath.status, 404);
  } finally {
    await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
  }
});

test('HTTP listener refuses public network binding', async () => {
  const server = createAuthenticatedHttpServer(policy, async () => {});
  await assert.rejects(() => listenLoopback(server, '0.0.0.0', 3000), /loopback/);
});

test('HTTP execution deadline cancels a stalled handler and frees the single request slot', { timeout: 10000 }, async () => {
  const oldLimit = process.env.SSH_MCP_HTTP_MAX_REQUESTS;
  const oldTimeout = process.env.SSH_MCP_HTTP_REQUEST_TIMEOUT_MS;
  process.env.SSH_MCP_HTTP_MAX_REQUESTS = '1';
  process.env.SSH_MCP_HTTP_REQUEST_TIMEOUT_MS = '1000';
  let calls = 0;
  let signal;
  const server = createAuthenticatedHttpServer(policy, async context => {
    calls++;
    if (calls === 1) {
      signal = context.signal;
      await new Promise(() => {}); // The boundary must release even a noncooperating handler.
    } else context.response.writeHead(200).end('next');
  });
  if (oldLimit === undefined) delete process.env.SSH_MCP_HTTP_MAX_REQUESTS;
  else process.env.SSH_MCP_HTTP_MAX_REQUESTS = oldLimit;
  if (oldTimeout === undefined) delete process.env.SSH_MCP_HTTP_REQUEST_TIMEOUT_MS;
  else process.env.SSH_MCP_HTTP_REQUEST_TIMEOUT_MS = oldTimeout;
  const { port } = await listenLoopback(server, '127.0.0.1', 0);
  try {
    const options = { method: 'POST', headers: { authorization: 'Bearer ' + token } };
    const response = await fetch('http://127.0.0.1:' + port + '/mcp', options);
    assert.equal(response.status, 504);
    await response.text();
    assert.equal(signal.aborted, true);
    const next = await fetch('http://127.0.0.1:' + port + '/mcp', options);
    assert.equal(next.status, 200);
    assert.equal(await next.text(), 'next');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
