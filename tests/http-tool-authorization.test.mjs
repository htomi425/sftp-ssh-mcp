import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';
import { resolveToolTarget } from '../build/tool-target.js';

const registry = {
  alpha: { host: '127.0.0.1', user: 'tester', password: 'unused', hostKeySha256: 'a'.repeat(64) },
  beta: { host: '127.0.0.2', user: 'tester', password: 'unused', hostKeySha256: 'b'.repeat(64) },
};
const aliceToken = 'a'.repeat(48);
const bobToken = 'b'.repeat(48);
const policy = parseHttpAccessPolicy(JSON.stringify([
  { id: 'alice', token: aliceToken, targets: ['alpha'] },
  { id: 'bob', token: bobToken, targets: ['beta'] },
]), new Set(Object.keys(registry)));

test('authenticated HTTP requests carry isolated principal permissions to tool target resolution', async () => {
  const seen = [];
  const server = createAuthenticatedHttpServer(policy, async ({ principal, request, response }) => {
    const body = await new Promise((resolve, reject) => {
      let text = '';
      request.on('data', chunk => {
        text += chunk.toString();
        if (text.length > 1024) { reject(new Error('oversized test body')); request.destroy(); }
      });
      request.on('end', () => resolve(text));
      request.on('error', reject);
    });
    const requestedName = JSON.parse(body).target;
    try {
      const target = resolveToolTarget(registry, requestedName, { principal }, 'http');
      seen.push({ id: principal.id, host: target.host });
      response.writeHead(200).end('authorized');
    } catch {
      response.writeHead(403).end('forbidden');
    }
  });
  const { port } = await listenLoopback(server, '127.0.0.1', 0);
  try {
    const url = `http://127.0.0.1:${port}/mcp`;
    const send = (token, target) => fetch(url, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    assert.equal((await send(aliceToken, 'alpha')).status, 200);
    assert.equal((await send(aliceToken, 'beta')).status, 403);
    assert.equal((await send(bobToken, 'alpha')).status, 403);
    assert.equal((await send(bobToken, 'beta')).status, 200);
    assert.equal((await send('c'.repeat(48), 'alpha')).status, 401);
    assert.deepEqual(seen, [
      { id: 'alice', host: '127.0.0.1' },
      { id: 'bob', host: '127.0.0.2' },
    ]);
  } finally {
    await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
  }
});
