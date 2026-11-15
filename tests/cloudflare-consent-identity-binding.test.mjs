import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHmac } from 'node:crypto';
import { createConsentIdentityBinding } from '../integrations/cloudflare/consent-identity-binding.mjs';

const secret = 'test-only-consent-binding-secret-2026-long-enough';
const alice = { issuer: 'https://login.example', id: 'alice' };
const bob = { issuer: 'https://login.example', id: 'bob' };
const binding = createConsentIdentityBinding(secret);

function signed(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return data + '.' + createHmac('sha256', secret).update(data).digest('base64url');
}

test('consent identity binding validates issuer, subject and unmodified handle', async () => {
  const token = await binding.issue('opaque-provider-handle', alice);
  assert.equal(await binding.verify(token, alice), 'opaque-provider-handle');
  assert.equal(await binding.verify(token, bob), null);
  assert.equal(await binding.verify(token, { ...alice, issuer: 'https://other.example' }), null);
});

test('consent identity binding rejects modified signatures and payloads', async () => {
  const token = await binding.issue('opaque-provider-handle', alice);
  const [data, mac] = token.split('.');
  const altered = Buffer.from(JSON.stringify({
    ...JSON.parse(Buffer.from(data, 'base64url').toString()),
    subject: 'bob',
  })).toString('base64url');
  assert.equal(await binding.verify(altered + '.' + mac, bob), null);
  assert.equal(await binding.verify(data + '.' + (mac[0] === 'A' ? 'B' : 'A') + mac.slice(1), alice), null);
  assert.equal(await binding.verify('not-a-valid-token', alice), null);
});

test('consent identity binding rejects expired and excessive lifetime', async () => {
  const now = Date.now();
  const payload = { handle: 'opaque-provider-handle', issuer: alice.issuer, subject: alice.id };
  assert.equal(await binding.verify(signed({ ...payload, expires: now - 1000 }), alice), null);
  assert.equal(await binding.verify(signed({ ...payload, expires: now + 3600000 }), alice), null);
  assert.equal(await binding.verify(signed({ ...payload, expires: now + 60000 }), alice), payload.handle);
});

test('consent signing secret is mandatory', () => {
  assert.throws(() => createConsentIdentityBinding('short'), /at least 32/);
});

test('consent binding rejects oversized and noncanonical encoded input', async () => {
  const token = await binding.issue('provider-handle', alice);
  assert.equal(await binding.verify('a'.repeat(2049), alice), null);
  assert.equal(await binding.verify(token + '.', alice), null);
  assert.equal(await binding.verify(token.replace('.', '=' + '.'), alice), null);
  assert.equal(await binding.verify(token.split('.')[0] + '.AAAA', alice), null);
  await assert.rejects(() => binding.issue('a'.repeat(1025), alice), /Invalid provider consent handle/);
});

test('consent identity binding rejects missing and malformed signed claims', async () => {
  const valid = {
    handle: 'opaque-provider-handle', issuer: alice.issuer,
    subject: alice.id, expires: Date.now() + 60000,
  };
  for (const name of ['handle', 'issuer', 'subject', 'expires']) {
    const claims = { ...valid };
    delete claims[name];
    assert.equal(await binding.verify(signed(claims), alice), null,
      'missing ' + name + ' must be rejected');
  }
  for (const [name, value] of [
    ['handle', null], ['handle', 123], ['handle', ''],
    ['issuer', null], ['subject', null],
    ['expires', null], ['expires', 'future'], ['expires', 1.5],
  ]) {
    assert.equal(await binding.verify(signed({ ...valid, [name]: value }), alice), null,
      'invalid ' + name + ' must be rejected');
  }
});
