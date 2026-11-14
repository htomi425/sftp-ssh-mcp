import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthorizationHandler } from '../integrations/cloudflare/authorization-handler.mjs';

function setup(user = { id: 'alice', issuer: 'https://login.example' }) {
  const calls = [];
  const oauth = {
    async parseAuthRequest() { calls.push('parse'); return { scope: ['mcp:invoke'] }; },
    async describeConsent() { calls.push('describe'); return {}; },
    async beginConsent() { calls.push('begin'); return { handle: 'opaque' }; },
    async denyConsent() { calls.push('deny'); return { headers: new Headers({ Location: 'https://client.example/denied' }) }; },
    async approveConsent(_req, handle, opts) { calls.push(['approve', handle, opts.scope]); return { request: { scope: ['mcp:invoke'] } }; },
    async completeAuthorization(opts) { calls.push(['complete', opts]); return { redirectTo: 'https://client.example/callback?code=ok' }; },
  };
  const handler = createAuthorizationHandler({
    getOAuthApi: () => oauth,
    authenticateUser: async () => user,
    renderConsent: async () => new Response('Consent required'),
  });
  return { handler, oauth, calls };
}
const get = () => new Request('https://auth.example/authorize');
const post = (decision, extra = {}) => new Request('https://auth.example/authorize', {
  method: 'POST', body: new URLSearchParams({ handle: 'opaque', decision, ...extra }),
});
test('GET only renders consent; no token is issued', async () => {
  const { handler, calls } = setup();
  assert.equal((await handler.fetch(get(), {})).status, 200);
  assert.deepEqual(calls, ['parse', 'describe', 'begin']);
});
test('unauthenticated request never invokes OAuth API', async () => {
  const { handler, calls } = setup(null);
  assert.equal((await handler.fetch(get(), {})).status, 401);
  assert.deepEqual(calls, []);
});
test('explicit approval uses stored request and trusted user identity', async () => {
  const { handler, calls } = setup();
  const response = await handler.fetch(post('approve', { userId: 'admin', scope: 'admin' }), {});
  assert.equal(response.status, 302);
  const completed = calls.find(c => Array.isArray(c) && c[0] === 'complete')[1];
  assert.equal(completed.userId, 'alice');
  assert.deepEqual(completed.scope, ['mcp:invoke']);
  assert.deepEqual(completed.props, { userId: 'alice', issuer: 'https://login.example' });
});
test('denial and invalid decisions do not grant access', async () => {
  const { handler, calls } = setup();
  assert.equal((await handler.fetch(post('deny'), {})).status, 302);
  assert.equal((await handler.fetch(post('other'), {})).status, 400);
  assert.equal(calls.some(c => Array.isArray(c) && c[0] === 'complete'), false);
});
test('cross-origin consent POST is rejected', async () => {
  const { handler, calls } = setup();
  const response = await handler.fetch(new Request('https://auth.example/authorize', {
    method: 'POST', headers: { Origin: 'https://attacker.example' },
    body: new URLSearchParams({ handle: 'opaque', decision: 'approve' }),
  }), {});
  assert.equal(response.status, 403);
  assert.equal(calls.length, 0);
});
