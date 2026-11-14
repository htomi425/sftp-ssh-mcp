import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createConsentAuthorizationWorker } from '../integrations/cloudflare/consent-authorization-worker.mjs';

test('composed authorization Worker requires verified session and explicit consent', async () => {
  const calls = [];
  const validToken = 'a'.repeat(48);
  const oauth = {
    async parseAuthRequest() { calls.push('parse'); return { scope: ['mcp:invoke'] }; },
    async describeConsent() { calls.push('describe'); return {
      client: { client_name: '<img src=x onerror=alert(1)>' }, scope: ['mcp:invoke'],
    }; },
    async beginConsent() { calls.push('begin'); return { handle: 'provider-handle' }; },
    async approveConsent(_request, handle, options) {
      calls.push(['approve', handle, options.scope]);
      return { request: { scope: ['mcp:invoke'] } };
    },
    async denyConsent() { calls.push('deny'); return {
      headers: new Headers({ Location: 'https://client.example/denied' }),
    }; },
    async completeAuthorization(options) {
      calls.push(['complete', options]);
      return { redirectTo: 'https://client.example/callback?code=authorized' };
    },
  };
  const worker = createConsentAuthorizationWorker({
    authorizationServer: {
      getOAuthApi: () => oauth,
      fetch: async () => new Response('provider endpoint'),
      validateToken: async () => ({ active: false }),
    },
    verifySession: async token => token === validToken
      ? { id: 'alice', issuer: 'https://login.example' } : null,
  });
  const url = 'https://auth.example/authorize';
  const get = cookie => new Request(url, {
    headers: cookie ? { Cookie: '__Host-ssh_mcp_session=' + cookie } : {},
  });
  const post = (cookie, decision) => new Request(url, {
    method: 'POST',
    headers: { Cookie: '__Host-ssh_mcp_session=' + cookie,
      Origin: 'https://auth.example',
      'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ handle: 'provider-handle', decision }),
  });
  assert.equal((await worker.fetch(get(null), {})).status, 401);
  assert.equal((await worker.fetch(get('b'.repeat(48)), {})).status, 401);
  assert.deepEqual(calls, []);
  const consent = await worker.fetch(get(validToken), {});
  assert.equal(consent.status, 200);
  const html = await consent.text();
  assert.match(html, /Approve/);
  assert.match(html, /Deny/);
  assert.match(html, /provider-handle/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.equal(calls.includes('begin'), true);
  assert.equal(calls.some(call => Array.isArray(call) && call[0] === 'complete'), false);
  assert.equal((await worker.fetch(post('b'.repeat(48), 'approve'), {})).status, 401);
  assert.equal(calls.some(call => Array.isArray(call) && call[0] === 'complete'), false);
  assert.equal((await worker.fetch(post(validToken, 'deny'), {})).status, 302);
  assert.equal(calls.some(call => Array.isArray(call) && call[0] === 'complete'), false);
  const approved = await worker.fetch(post(validToken, 'approve'), {});
  assert.equal(approved.status, 302);
  const completion = calls.find(call => Array.isArray(call) && call[0] === 'complete')[1];
  assert.equal(completion.userId, 'alice');
  assert.deepEqual(completion.props, { userId: 'alice', issuer: 'https://login.example' });
  assert.deepEqual(completion.scope, ['mcp:invoke']);
});
