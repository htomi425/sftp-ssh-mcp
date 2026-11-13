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
