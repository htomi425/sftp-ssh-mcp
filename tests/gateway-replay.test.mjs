import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createGatewayAssertionVerifier } from '../build/gateway-assertion.js';
import { createInMemoryReplayCache, createReplayProtectedGatewayVerifier } from '../build/gateway-replay.js';

const keys = generateKeyPairSync('ed25519');
const now = 1800000000;
const issuer = 'https://gateway.example';
const audience = 'ssh-mcp-origin';
const verifier = createGatewayAssertionVerifier({ issuer, audience, publicKeyPem: keys.publicKey.export({ format: 'pem', type: 'spki' }) });
const encode = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
function assertion(jti) {
  const header = encode({ alg: 'EdDSA', typ: 'JWT' });
  const body = encode({ iss: issuer, sub: 'alice', aud: audience, iat: now - 1, nbf: now - 1, exp: now + 30, jti });
  const message = header + '.' + body;
  return message + '.' + sign(null, Buffer.from(message), keys.privateKey).toString('base64url');
}

test('a signed gateway assertion is accepted exactly once', () => {
  const gate = createReplayProtectedGatewayVerifier(verifier, createInMemoryReplayCache());
  const token = assertion('replay_nonce_000001');
  assert.deepEqual(gate.verifyOnce(token, now), { issuer, subject: 'alice' });
  assert.throws(() => gate.verifyOnce(token, now), /replayed/);
  assert.deepEqual(gate.verifyOnce(assertion('replay_nonce_000002'), now), { issuer, subject: 'alice' });
});

test('cache capacity fails closed and expired entries can be reclaimed', () => {
  const cache = createInMemoryReplayCache(1);
  assert.equal(cache.claim('a', now + 2, now), true);
  assert.equal(cache.claim('b', now + 30, now), false);
  assert.equal(cache.claim('a', now + 30, now), false);
  assert.equal(cache.claim('b', now + 30, now + 3), true);
  assert.equal(cache.claim('b', now + 30, now + 3), false);
});

test('cache rejects malformed identifiers and invalid capacity', () => {
  const cache = createInMemoryReplayCache();
  assert.equal(cache.claim('', now + 30, now), false);
  assert.equal(cache.claim('a', now, now), false);
  assert.throws(() => createInMemoryReplayCache(0), /capacity/);
});
