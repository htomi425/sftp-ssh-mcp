import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseIdentityTargetPolicy } from '../build/identity-target-policy.js';

const known = new Set(['alpha', 'beta']);
const entries = [
  { issuer: 'https://idp.example', subject: 'alice', targets: ['alpha'] },
  { issuer: 'https://other.example', subject: 'alice', targets: ['beta'] },
];

test('identity mapping isolates the same subject across issuers', () => {
  const policy = parseIdentityTargetPolicy(JSON.stringify(entries), known);
  assert.deepEqual([...policy.resolve({ issuer: 'https://idp.example', subject: 'alice' }).targets], ['alpha']);
  assert.deepEqual([...policy.resolve({ issuer: 'https://other.example', subject: 'alice' }).targets], ['beta']);
  assert.throws(() => policy.resolve({ issuer: 'https://idp.example', subject: 'bob' }), /not authorized/);
  assert.throws(() => policy.resolve({ issuer: 'https://IDP.example', subject: 'alice' }), /not authorized/);
});

test('identity mapping rejects unsafe configuration', () => {
  assert.throws(() => parseIdentityTargetPolicy(undefined, known), /required/);
  assert.throws(() => parseIdentityTargetPolicy('[]', known), /1 to 256/);
  assert.throws(() => parseIdentityTargetPolicy(JSON.stringify([...entries, entries[0]]), known), /Duplicate identity mapping/);
  assert.throws(() => parseIdentityTargetPolicy(JSON.stringify([{ ...entries[0], targets: ['alpha', 'alpha'] }]), known), /Duplicate identity target/);
  assert.throws(() => parseIdentityTargetPolicy(JSON.stringify([{ ...entries[0], targets: ['missing'] }]), known), /unknown or empty/);
  assert.throws(() => parseIdentityTargetPolicy(JSON.stringify([{ ...entries[0], role: 'admin' }]), known), /Unknown identity mapping field/);
  assert.throws(() => parseIdentityTargetPolicy(JSON.stringify([{ ...entries[0], issuer: '' }]), known), /Invalid verified identity/);
  assert.throws(() => parseIdentityTargetPolicy(JSON.stringify([{ ...entries[0], subject: '' }]), known), /Invalid verified identity/);
});
