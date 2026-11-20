import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createGatewayAssertionVerifier } from '../build/gateway-assertion.js';
import { createInMemoryReplayCache } from '../build/gateway-replay.js';
import { createRequestBoundGatewayVerifier } from '../build/gateway-request-binding.js';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const issuer = 'https://gateway.example';
const audience = 'ssh-mcp-origin';
const now = 1800000000;
const verifier = createGatewayAssertionVerifier({ issuer, audience, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) });
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const body = Buffer.from('{"jsonrpc":"2.0"}');
const request = { method: 'POST', path: '/mcp', body };
function token(overrides = {}) {
  const claims = {
    iss: issuer, sub: 'alice', aud: audience, iat: now - 1, nbf: now - 1,
    exp: now + 30, jti: 'request_nonce_123456',
    htm: 'POST', htu: '/mcp', body_sha256: createHash('sha256').update(body).digest('base64url'),
    ...overrides,
  };
  const signingInput = encode({ alg: 'EdDSA', typ: 'JWT' }) + '.' + encode(claims);
  return signingInput + '.' + sign(null, Buffer.from(signingInput), privateKey).toString('base64url');
}

test('accepts a correctly bound request only once', () => {
  const gate = createRequestBoundGatewayVerifier(verifier, createInMemoryReplayCache());
  const signed = token();
  assert.deepEqual(gate.verifyOnce(signed, request, now), { issuer, subject: 'alice' });
  assert.throws(() => gate.verifyOnce(signed, request, now), /replayed/);
});

test('rejects method, path, raw body and digest mismatch without consuming nonce', () => {
  const gate = createRequestBoundGatewayVerifier(verifier, createInMemoryReplayCache());
  const signed = token();
  assert.throws(() => gate.verifyOnce(signed, { ...request, method: 'GET' }, now), /binding/);
  assert.throws(() => gate.verifyOnce(signed, { ...request, path: '/other' }, now), /binding/);
  assert.throws(() => gate.verifyOnce(signed, { ...request, body: Buffer.from('{"jsonrpc": "2.0"}') }, now), /digest/);
  assert.throws(() => gate.verifyOnce(token({ body_sha256: 'A'.repeat(43) }), request, now), /digest/);
  assert.deepEqual(gate.verifyOnce(signed, request, now), { issuer, subject: 'alice' });
});

test('rejects absent binding and invalid signature', () => {
  const gate = createRequestBoundGatewayVerifier(verifier, createInMemoryReplayCache());
  assert.throws(() => gate.verifyOnce(token({ htm: undefined }), request, now), /binding/);
  const signed = token();
  const [head, payload, sig] = signed.split('.');
  assert.throws(() => gate.verifyOnce([head, payload, (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)].join('.'), request, now), /signature/);
});
