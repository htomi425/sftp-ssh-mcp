import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHostKeyVerifier, normalizeHostKeySha256 } from '../build/ssh/host-key.js';

const a = 'a'.repeat(64);
const b = 'b'.repeat(64);

test('normalizes expected SHA-256 hex fingerprints', () => {
  assert.equal(normalizeHostKeySha256('SHA256:' + a.toUpperCase()), a);
});
test('rejects missing or malformed fingerprints', () => {
  for (const fingerprint of ['', 'sha256:abc', 'z'.repeat(64), 'a'.repeat(63)]) {
    assert.throws(() => normalizeHostKeySha256(fingerprint), /fingerprint/);
  }
});
test('accepts only matching fingerprints', () => {
  const verify = createHostKeyVerifier(a);
  assert.equal(verify(a), true);
  assert.equal(verify(a.toUpperCase()), true);
  assert.equal(verify(b), false);
  assert.equal(verify('invalid'), false);
});
