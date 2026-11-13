import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseHttpAccessPolicy } from '../build/http-access.js';

const targets = new Set(['alpha', 'beta']);
const tokenA = 'a'.repeat(48);
const tokenB = 'b'.repeat(48);
const credentials = JSON.stringify([
  { id: 'alice', token: tokenA, targets: ['alpha'] },
  { id: 'bob', token: tokenB, targets: ['beta'] },
]);

test('HTTP authentication fails closed for missing, malformed, or unknown credentials', () => {
  assert.throws(() => parseHttpAccessPolicy(undefined, targets), /required/);
  const policy = parseHttpAccessPolicy(credentials, targets);
  for (const value of [undefined, '', 'Basic ' + tokenA, 'Bearer ' + tokenA.slice(0, 8), 'Bearer ' + 'c'.repeat(48), 'bearer ' + tokenA]) {
    assert.throws(() => policy.authenticate(value), /authentication/);
  }
});

test('HTTP principals can access only their explicitly authorized targets', () => {
  const policy = parseHttpAccessPolicy(credentials, targets);
  const alice = policy.authenticate('Bearer ' + tokenA);
  const bob = policy.authenticate('Bearer ' + tokenB);
  assert.equal(alice.id, 'alice');
  assert.equal(bob.id, 'bob');
  assert.doesNotThrow(() => policy.authorize(alice, 'alpha'));
  assert.doesNotThrow(() => policy.authorize(bob, 'beta'));
  assert.throws(() => policy.authorize(alice, 'beta'), /denied/);
  assert.throws(() => policy.authorize(bob, 'alpha'), /denied/);
  assert.throws(() => policy.authorize(alice, 'missing'), /denied/);
});

test('HTTP policy rejects malformed, duplicate, and unauthorized credential definitions', () => {
  const bad = [
    'not json', '{}', '[]',
    JSON.stringify([{ id: 'alice', token: 'short', targets: ['alpha'] }]),
    JSON.stringify([{ id: 'alice', token: tokenA, targets: ['unknown'] }]),
    JSON.stringify([{ id: 'alice', token: tokenA, targets: [] }]),
    JSON.stringify([{ id: 'alice', token: tokenA, targets: ['alpha', 'alpha'] }]),
    JSON.stringify([{ id: 'alice', token: tokenA, targets: ['alpha'], typo: true }]),
    JSON.stringify([{ id: 'alice', token: tokenA, targets: ['alpha'] }, { id: 'alice', token: tokenB, targets: ['beta'] }]),
    JSON.stringify([{ id: 'alice', token: tokenA, targets: ['alpha'] }, { id: 'bob', token: tokenA, targets: ['beta'] }]),
  ];
  for (const value of bad) assert.throws(() => parseHttpAccessPolicy(value, targets), undefined, value);
});
