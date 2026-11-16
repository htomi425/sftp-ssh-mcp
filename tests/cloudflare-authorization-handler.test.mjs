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
    async approveConsent(_req, handle, opts) { calls.push(['approve', handle, opts.scope]); return { request: { scope: ['mcp:invoke'] }, headers: new Headers({ 'Set-Cookie': '__Host-oauth_consent=; Path=/; Secure; HttpOnly; Max-Age=0', 'Cache-Control': 'no-store' }) }; },
    async completeAuthorization(opts) { calls.push(['complete', opts]); return { redirectTo: 'https://client.example/callback?code=ok' }; },
  };
  const handler = createAuthorizationHandler({
    getOAuthApi: () => oauth,
    authenticateUser: async () => user,
    bindConsent: {
      async issue(handle) { return handle; },
      async verify(handle) { return handle; },
    },
    renderConsent: async () => new Response('Consent required'),
  });
  return { handler, oauth, calls };
}
const get = () => new Request('https://auth.example/authorize');
const post = (decision, extra = {}) => new Request('https://auth.example/authorize', {
  method: 'POST', headers: { Origin: 'https://auth.example' },
  body: new URLSearchParams({ handle: 'opaque', decision, ...extra }),
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
  const response = await handler.fetch(post('approve'), {});
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.match(response.headers.get('Set-Cookie') ?? '', /Max-Age=0/);
  assert.equal(response.headers.get('Location'), 'https://client.example/callback?code=ok');
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

test('consent POST requires same-origin form submission', async () => {
  const { handler, calls } = setup();
  for (const headers of [
    {},
    { Origin: 'null' },
    { Origin: 'not-a-url' },
    { Origin: 'https://attacker.example' },
    { Origin: 'https://auth.example', 'Content-Type': 'application/json' },
  ]) {
    const response = await handler.fetch(new Request('https://auth.example/authorize', {
      method: 'POST', headers,
      body: headers['Content-Type'] === 'application/json'
        ? JSON.stringify({ handle: 'opaque', decision: 'approve' })
        : new URLSearchParams({ handle: 'opaque', decision: 'approve' }),
    }), {});
    assert.ok([403, 415].includes(response.status), String(response.status));
  }
  assert.deepEqual(calls, [], 'invalid consent submissions never invoke provider');
});
test('ambiguous or injected consent fields are rejected before approval', async () => {
  const { handler, calls } = setup();
  for (const body of [
    'handle=opaque&handle=other&decision=approve',
    'handle=opaque&decision=approve&decision=deny',
    'handle=opaque&decision=approve&userId=admin',
    'handle=opaque&decision=approve&scope=mcp%3Aadmin',
  ]) {
    const response = await handler.fetch(new Request('https://auth.example/authorize', {
      method: 'POST', headers: {
        Origin: 'https://auth.example',
        'Content-Type': 'application/x-www-form-urlencoded',
      }, body,
    }), {});
    assert.equal(response.status, 400);
  }
  assert.deepEqual(calls, [], 'no ambiguous submission may reach OAuth approval');
});

test('authorization handler rejects missing or incomplete identity binding', () => {
  const required = {
    getOAuthApi: () => ({}),
    authenticateUser: async () => ({ id: 'alice', issuer: 'https://login.example' }),
    renderConsent: async () => new Response('Consent'),
  };
  assert.throws(() => createAuthorizationHandler(required), /identity binding is required/);
  assert.throws(() => createAuthorizationHandler({
    ...required, bindConsent: { issue: async handle => handle },
  }), /identity binding is required/);
});

test('oversized consent POST is rejected before reaching OAuth provider', async () => {
  const { handler, calls } = setup();
  const url = 'https://auth.example/authorize';
  const headers = { Origin: 'https://auth.example',
    'Content-Type': 'application/x-www-form-urlencoded' };
  const oversizedBody = 'handle=opaque&decision=approve&padding=' + 'x'.repeat(8192);
  const declared = await handler.fetch(new Request(url, {
    method: 'POST', headers: { ...headers, 'Content-Length': String(oversizedBody.length) },
    body: oversizedBody,
  }), {});
  assert.equal(declared.status, 413);
  // The body stream has no Content-Length, but still must be bounded.
  const chunked = await handler.fetch(new Request(url, {
    method: 'POST', headers, body: new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('handle=opaque&decision=approve&'));
        controller.enqueue(new TextEncoder().encode('x'.repeat(8192)));
        controller.close();
      },
    }), duplex: 'half',
  }), {});
  assert.equal(chunked.status, 413);
  assert.deepEqual(calls, [], 'oversized POST never invokes the provider');
});

test('oversized OAuth GET query is rejected before authentication and provider parsing', async () => {
  const { handler, calls } = setup();
  const url = 'https://auth.example/authorize?state=' + 'x'.repeat(8192);
  const response = await handler.fetch(new Request(url), {});
  assert.equal(response.status, 414);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.deepEqual(calls, [], 'oversized query must not invoke OAuth provider');
});

test('normal OAuth GET query reaches consent flow', async () => {
  const { handler, calls } = setup();
  const response = await handler.fetch(new Request(
    'https://auth.example/authorize?client_id=client&state=abc',
  ), {});
  assert.equal(response.status, 200);
  assert.deepEqual(calls, ['parse', 'describe', 'begin']);
});

test('declared oversized consent POST is rejected before session verifier', async () => {
  let authentications = 0;
  let providerLookups = 0;
  const handler = createAuthorizationHandler({
    getOAuthApi() { providerLookups++; return {}; },
    async authenticateUser() { authentications++; return { id: 'alice', issuer: 'https://login.example' }; },
    bindConsent: { async issue(value) { return value; }, async verify(value) { return value; } },
    renderConsent: async () => new Response('consent'),
  });
  const url = 'https://auth.example/authorize';
  const response = await handler.fetch(new Request(url, {
    method: 'POST',
    headers: {
      Origin: 'https://auth.example',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': '8193',
    },
    body: 'handle=opaque&decision=approve',
  }), {});
  assert.equal(response.status, 413);
  assert.equal(authentications, 0, 'oversized POST must not verify sessions');
  assert.equal(providerLookups, 0, 'oversized POST must not invoke OAuth provider');
});

test('oversized streaming consent POST is rejected before session verifier', async () => {
  let authentications = 0;
  let providerLookups = 0;
  const handler = createAuthorizationHandler({
    getOAuthApi() { providerLookups++; return {}; },
    async authenticateUser() {
      authentications++;
      return { id: 'alice', issuer: 'https://login.example' };
    },
    bindConsent: { async issue(value) { return value; }, async verify(value) { return value; } },
    renderConsent: async () => new Response('consent'),
  });
  const response = await handler.fetch(new Request('https://auth.example/authorize', {
    method: 'POST',
    headers: {
      Origin: 'https://auth.example',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('handle=opaque&decision=approve&'));
        controller.enqueue(new TextEncoder().encode('padding=' + 'x'.repeat(8192)));
        controller.close();
      },
    }),
    duplex: 'half',
  }), {});
  assert.equal(response.status, 413);
  assert.equal(authentications, 0, 'oversized streaming body must not verify sessions');
  assert.equal(providerLookups, 0, 'oversized streaming body must not invoke OAuth provider');
});

for (const stalledCancel of [false, true]) {
  test('oversized open consent stream rejects without waiting for ' +
    (stalledCancel ? 'upstream cancellation' : 'EOF'), { timeout: 3000 }, async () => {
    let authentications = 0;
    let providerLookups = 0;
    let cancelled = false;
    const handler = createAuthorizationHandler({
      getOAuthApi() { providerLookups++; return {}; },
      async authenticateUser() { authentications++; return { id: 'alice', issuer: 'https://login.example' }; },
      bindConsent: { async issue(value) { return value; }, async verify(value) { return value; } },
      renderConsent: async () => new Response('consent'),
    });
    const request = new Request('https://auth.example/authorize', {
      method: 'POST',
      headers: { Origin: 'https://auth.example', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('handle=opaque&decision=approve&'));
          controller.enqueue(new Uint8Array(8192));
          // The sender deliberately never closes its body.
        },
        cancel() {
          cancelled = true;
          if (stalledCancel) return new Promise(() => {});
        },
      }),
      duplex: 'half',
    });
    const response = await handler.fetch(request, {});
    assert.equal(response.status, 413);
    assert.equal(cancelled, true);
    assert.equal(authentications, 0);
    assert.equal(providerLookups, 0);
  });
}
