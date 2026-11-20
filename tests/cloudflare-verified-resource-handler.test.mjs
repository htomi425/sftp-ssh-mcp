import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createVerifiedResourceHandler } from '../integrations/cloudflare/verified-resource-handler.mjs';

test('validated OAuth context forwards immutable identity and scopes', async () => {
  const calls = [];
  const handler = createVerifiedResourceHandler({
    forward: async (request, env, identity) => {
      calls.push({ request, env, identity });
      return new Response('ok');
    },
    insufficientScope: () => new Response('insufficient_scope', { status: 403 }),
  });
  const request = new Request('https://ssh-mcp.example/mcp', { method: 'POST' });
  const env = {};
  const result = await handler.fetch(request, env, {
    auth: { scope: ['mcp:invoke'] },
    props: { issuer: 'https://auth.example', userId: 'alice' },
  });
  assert.equal(result.status, 200);
  assert.deepEqual(calls[0].identity, {
    issuer: 'https://auth.example', subject: 'alice', scopes: ['mcp:invoke'],
  });
});
test('missing verified context, scope and user identity fail closed', async () => {
  let calls = 0;
  const handler = createVerifiedResourceHandler({
    forward: async () => { calls++; return new Response('ok'); },
    insufficientScope: () => new Response('insufficient_scope', { status: 403 }),
  });
  const request = new Request('https://ssh-mcp.example/mcp');
  assert.equal((await handler.fetch(request, {}, {})).status, 401);
  assert.equal((await handler.fetch(request, {}, { auth: { scope: [] }, props: { issuer: 'i', userId: 'a' } })).status, 403);
  assert.equal((await handler.fetch(request, {}, { auth: { scope: ['mcp:invoke'] }, props: { issuer: 'i' } })).status, 401);
  assert.equal(calls, 0);
});
