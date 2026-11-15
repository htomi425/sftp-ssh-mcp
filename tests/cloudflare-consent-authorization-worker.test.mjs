import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createConsentAuthorizationWorker, createEnvConsentAuthorizationWorker } from '../integrations/cloudflare/consent-authorization-worker.mjs';

test('composed authorization Worker requires verified session and explicit consent', async () => {
  const calls = [];
  const validToken = 'a'.repeat(48);
  let signedHandle;
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
    consentSigningSecret: 'isolated-test-consent-secret-not-for-production-2026',
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
    body: new URLSearchParams({ handle: signedHandle, decision }),
  });
  assert.equal((await worker.fetch(get(null), {})).status, 401);
  assert.equal((await worker.fetch(get('b'.repeat(48)), {})).status, 401);
  assert.deepEqual(calls, []);
  const consent = await worker.fetch(get(validToken), {});
  assert.equal(consent.status, 200);
  const html = await consent.text();
  assert.match(html, /Approve/);
  assert.match(html, /Deny/);
  signedHandle = html.match(/name="handle" value="([^"]+)"/)?.[1];
  assert.ok(signedHandle);
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

test('consent Worker fails closed when identity-signing secret is missing or weak', () => {
  const authorizationServer = {
    getOAuthApi: () => ({}),
    fetch: async () => new Response('provider endpoint'),
    validateToken: async () => ({ active: false }),
  };
  const verifySession = async () => ({ id: 'alice', issuer: 'https://login.example' });
  assert.throws(() => createConsentAuthorizationWorker({
    authorizationServer, verifySession,
  }), /Consent signing secret/);
  assert.throws(() => createConsentAuthorizationWorker({
    authorizationServer, verifySession, consentSigningSecret: 'unsafe',
  }), /Consent signing secret/);
});

test('runtime environment consent secret is required for authorization but not OAuth discovery', async () => {
  const token = 'v'.repeat(48);
  const secret = 'environment-only-oauth-secret-test-2026-strong';
  const calls = [];
  const oauth = {
    parseAuthRequest: async () => ({ scope: ['mcp:invoke'] }),
    describeConsent: async () => ({ scope: ['mcp:invoke'] }),
    beginConsent: async () => ({ handle: 'provider-handle',
      headers: new Headers({ 'Set-Cookie': '__Host-consent=opaque; Secure; Path=/' }) }),
    approveConsent: async (_req, handle) => {
      calls.push(['approve', handle]);
      return { request: { scope: ['mcp:invoke'] } };
    },
    completeAuthorization: async () => ({ redirectTo: 'https://client.example/callback?code=ok' }),
  };
  const server = {
    getOAuthApi: () => oauth,
    fetch: async () => new Response('discovery'),
    validateToken: async () => ({ active: false }),
  };
  const worker = createEnvConsentAuthorizationWorker({
    authorizationServer: server,
    verifySession: async value => value === token
      ? { id: 'alice', issuer: 'https://login.example' } : null,
  });
  const url = 'https://auth.example/authorize';
  const get = new Request(url, { headers: { Cookie: '__Host-ssh_mcp_session=' + token } });
  assert.equal((await worker.fetch(get, {})).status, 503);
  assert.equal((await worker.fetch(get, { OAUTH_CONSENT_SIGNING_SECRET: 'short' })).status, 503);
  assert.equal((await worker.fetch(new Request('https://auth.example/.well-known/oauth-authorization-server'), {})).status, 200);
  const env = { OAUTH_CONSENT_SIGNING_SECRET: secret };
  const consent = await worker.fetch(get, env);
  assert.equal(consent.status, 200);
  const handle = (await consent.text()).match(/name="handle" value="([^"]+)"/)?.[1];
  assert.ok(handle && handle !== 'provider-handle');
  const approved = await worker.fetch(new Request(url, {
    method: 'POST',
    headers: { Cookie: '__Host-ssh_mcp_session=' + token,
      Origin: 'https://auth.example', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ handle, decision: 'approve' }),
  }), env);
  assert.equal(approved.status, 302);
  assert.deepEqual(calls, [['approve', 'provider-handle']]);
  assert.equal((await worker.validateToken('resource', 'token', env)).active, false);
  assert.throws(() => createEnvConsentAuthorizationWorker({
    authorizationServer: server, verifySession: async () => null, secretBinding: '__proto__',
  }), /binding name/);
});
