import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, createPublicKey, verify as verifySignature, webcrypto } from 'node:crypto';
import { handleResourceRequest, forwardVerifiedIdentity } from '../integrations/cloudflare/resource-gateway.mjs';

const crypto = globalThis.crypto ?? webcrypto;
const keys = generateKeyPairSync('ed25519');
const privatePem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicKey = createPublicKey(keys.publicKey.export({ type: 'spki', format: 'pem' }));
const resource = 'https://ssh-mcp.example/mcp';
const settings = { resource, requiredScope: 'mcp:invoke' };
function setup() {
  const received = [];
  const env = {
    GATEWAY_PRIVATE_KEY: privatePem, GATEWAY_ISSUER: 'https://gateway.example',
    GATEWAY_AUDIENCE: 'ssh-mcp-origin',
    ORIGIN: { fetch: async req => { received.push(req); return new Response('ok'); } },
  };
  return { env, received };
}
const allowed = async (token, audience) => {
  assert.equal(token, 'valid_access_token_123456');
  assert.equal(audience, resource);
  return { issuer: 'https://idp.example', subject: 'alice', scopes: ['mcp:invoke'] };
};
const req = (headers = {}, body = '{"jsonrpc":"2.0"}') =>
  new Request(resource, { method: 'POST', headers: { Authorization: 'Bearer valid_access_token_123456', ...headers }, body });

test('gateway signs the exact forwarded bytes and strips forged identity headers', async () => {
  const { env, received } = setup();
  const response = await handleResourceRequest(req({ 'X-User': 'admin', 'X-Targets': 'root' }), env, allowed, settings);
  assert.equal(response.status, 200);
  assert.equal(received.length, 1);
  const upstream = received[0];
  assert.equal(upstream.headers.has('x-user'), false);
  assert.equal(upstream.headers.has('x-targets'), false);
  const jwt = upstream.headers.get('authorization').slice(7);
  const [head, payload, sig] = jwt.split('.');
  assert.equal(verifySignature(null, Buffer.from(head + '.' + payload), publicKey, Buffer.from(sig, 'base64url')), true);
  const claims = JSON.parse(Buffer.from(payload, 'base64url'));
  assert.equal(claims.sub, JSON.stringify(['https://idp.example', 'alice']));
  assert.equal(claims.htm, 'POST');
  assert.equal(claims.htu, '/mcp');
  const expectedDigest = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('{"jsonrpc":"2.0"}'))).toString('base64url');
  assert.equal(claims.body_sha256, expectedDigest);
  assert.equal(await upstream.text(), '{"jsonrpc":"2.0"}');
});

test('gateway denies invalid tokens, missing scopes, origins and unexpected routes', async () => {
  const { env, received } = setup();
  assert.equal((await handleResourceRequest(req({ Authorization: 'Bearer bad' }), env, allowed, settings)).status, 401);
  assert.equal((await handleResourceRequest(req(), env, async () => { throw new Error('expired'); }, settings)).status, 401);
  assert.equal((await handleResourceRequest(req(), env, async () => ({ issuer: 'i', subject: 's', scopes: [] }), settings)).status, 403);
  assert.equal((await handleResourceRequest(req({ Origin: 'https://evil.example' }), env, allowed, settings)).status, 403);
  assert.equal((await handleResourceRequest(new Request(resource + '/other'), env, allowed, settings)).status, 404);
  assert.equal(received.length, 0);
});

test('verified resource context signs gateway assertion without using caller bearer', async () => {
  const { env, received } = setup();
  const response = await forwardVerifiedIdentity(req({ Authorization: 'Bearer attacker_supplied' }), env, {
    issuer: 'https://idp.example', subject: 'alice', scopes: ['mcp:invoke'],
  }, settings);
  assert.equal(response.status, 200);
  assert.equal(received.length, 1);
  assert.notEqual(received[0].headers.get('authorization'), 'Bearer attacker_supplied');
  const jwt = received[0].headers.get('authorization').slice(7);
  const claims = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'));
  assert.equal(claims.sub, JSON.stringify(['https://idp.example', 'alice']));
});
