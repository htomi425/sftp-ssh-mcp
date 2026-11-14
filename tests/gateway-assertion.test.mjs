import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createGatewayAssertionVerifier } from '../build/gateway-assertion.js';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const issuer = 'https://gateway.example';
const audience = 'ssh-mcp-origin';
const now = 1800000000;
const verifier = createGatewayAssertionVerifier({
  issuer, audience, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
});
const encode = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
function jwt(claims, header = { alg: 'EdDSA', typ: 'JWT' }) {
  const input = encode(header) + '.' + encode(claims);
  return input + '.' + sign(null, Buffer.from(input), privateKey).toString('base64url');
}
const valid = () => ({ iss: issuer, sub: 'alice', aud: audience, iat: now - 5, nbf: now - 5, exp: now + 30, jti: 'unique_request_12345' });

test('verifies signed gateway identity without assigning SSH permissions', () => {
  assert.deepEqual(verifier.verify(jwt(valid()), now), { issuer, subject: 'alice' });
});

test('rejects invalid signature, unsupported header and malformed tokens', () => {
  const token = jwt(valid());
  const [header, payload, signature] = token.split('.');
  const changedFirstChar = signature[0] === 'A' ? 'B' : 'A';
  const tampered = [header, payload, changedFirstChar + signature.slice(1)].join('.');
  assert.throws(() => verifier.verify(tampered, now), /signature|encoding/);
  assert.throws(() => verifier.verify(jwt(valid(), { alg: 'none', typ: 'JWT' }), now), /header/);
  assert.throws(() => verifier.verify(jwt(valid(), { alg: 'EdDSA', typ: 'JWT', kid: 'untrusted' }), now), /header/);
  assert.throws(() => verifier.verify('invalid', now), /format/);
});

test('rejects issuer, audience, missing nonce, and time violations', () => {
  for (const change of [
    { iss: 'https://other.example' },
    { aud: 'other-origin' },
    { jti: '' },
    { exp: now },
    { exp: now + 301 },
    { iat: now + 60 },
    { nbf: now + 60 },
    { sub: '' },
  ]) {
    assert.throws(() => verifier.verify(jwt({ ...valid(), ...change }), now));
  }
});

test('rejects non-Ed25519 verification keys', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(() => createGatewayAssertionVerifier({ issuer, audience, publicKeyPem: rsa.publicKey.export({ type: 'spki', format: 'pem' }) }), /Ed25519/);
});
