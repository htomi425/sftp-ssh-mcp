import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthorizationWorker, createAuthorizationEntrypoint } from '../integrations/cloudflare/authorization-worker.mjs';
import { createResourceWorker } from '../integrations/cloudflare/resource-worker.mjs';

test('authorization Worker delegates discovery and exposes Service Binding token validation', async () => {
  const calls = [];
  const server = {
    getOAuthApi() { return { parseAuthRequest: async () => ({ scope: ['mcp:invoke'] }), describeConsent: async () => ({}), beginConsent: async () => ({ handle: 'h' }) }; },
    fetch() { calls.push('discovery'); return new Response('metadata'); },
    validateToken(resource, token, env) { calls.push([resource, token, env]); return { active: true }; },
  };
  const worker = createAuthorizationWorker({
    authorizationServer: server,
    authenticateUser: async () => ({ id: 'alice', issuer: 'https://idp.example' }),
    bindConsent: { issue: async handle => handle, verify: async handle => handle },
    renderConsent: async () => new Response('consent'),
  });
  assert.equal((await worker.fetch(new Request('https://auth.example/authorize'), {})).status, 200);
  assert.equal((await worker.fetch(new Request('https://auth.example/.well-known/oauth-authorization-server'), {})).status, 200);
  assert.deepEqual(worker.validateToken('https://mcp.example/mcp', 'token', {}), { active: true });
  assert.equal(calls[0], 'discovery');
});

test('resource Worker delegates verification to private binding and rejects missing binding', () => {
  let options;
  class FakeResourceServer { constructor(config) { options = config; } }
  createResourceWorker({
    OAuthResourceServer: FakeResourceServer,
    insufficientScope: () => new Response('insufficient', { status: 403 }),
    resourceUrl: 'https://mcp.example/mcp',
    authorizationServerUrl: 'https://auth.example',
  });
  assert.equal(options.resourceMetadata.resource, 'https://mcp.example/mcp');
  assert.deepEqual(options.requiredScopes, ['mcp:invoke']);
  assert.throws(() => options.validateToken({}), /Service Binding/);
  const validateToken = () => true;
  assert.equal(options.validateToken({ AUTH_SERVER: { validateToken } }), validateToken);
});

test('resource Worker refuses unverified context before origin forwarding', async () => {
  let options;
  class FakeResourceServer { constructor(config) { options = config; } }
  createResourceWorker({
    OAuthResourceServer: FakeResourceServer,
    insufficientScope: () => new Response('insufficient', { status: 403 }),
    resourceUrl: 'https://mcp.example/mcp',
    authorizationServerUrl: 'https://auth.example',
  });
  const request = new Request('https://mcp.example/mcp');
  assert.equal((await options.handler.fetch(request, {}, {})).status, 401);
  assert.equal((await options.handler.fetch(request, {}, {
    auth: { scope: [] }, props: { issuer: 'https://idp.example', userId: 'alice' },
  })).status, 403);
});

test('authorization Service Binding RPC uses entrypoint env, not client input', async () => {
  const trustedEnv = { OAUTH_KV: 'trusted' };
  const calls = [];
  const worker = {
    fetch(request, env, ctx) { calls.push(['fetch', env, ctx]); return new Response('ok'); },
    validateToken(resource, token, env) {
      calls.push(['validate', resource, token, env]);
      return { active: true };
    },
  };
  class FakeEntrypoint {
    constructor() { this.env = trustedEnv; this.ctx = { waitUntil() {} }; }
  }
  const AuthServer = createAuthorizationEntrypoint(FakeEntrypoint, worker);
  const entrypoint = new AuthServer();
  assert.equal((await entrypoint.fetch(new Request('https://auth.example/'))).status, 200);
  assert.deepEqual(entrypoint.validateToken('https://mcp.example/mcp', 'secret'), { active: true });
  assert.equal(calls[0][1], trustedEnv);
  assert.equal(calls[1][3], trustedEnv);
});
