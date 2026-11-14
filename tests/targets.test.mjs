import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseTargets, selectTarget } from '../build/ssh/targets.js';

const digest = 'a'.repeat(64);
const first = { host: '127.0.0.1', user: 'alice', key: '/tmp/alice', hostKeySha256: digest };
const second = { host: '192.0.2.10', user: 'bob', password: 'test', hostKeySha256: 'b'.repeat(64) };

test('legacy configuration becomes default target', () => {
  const targets = parseTargets(undefined, first);
  assert.equal(selectTarget(targets).user, 'alice');
});
test('multiple named targets require explicit selection', () => {
  const targets = parseTargets(JSON.stringify({ alpha: first, beta: second }), undefined);
  assert.equal(selectTarget(targets, 'beta').user, 'bob');
  assert.throws(() => selectTarget(targets), /ambiguous/);
  assert.throws(() => selectTarget(targets, 'missing'), /Unknown/);
});
test('rejects malformed or insecure target configuration', () => {
  assert.throws(() => parseTargets('{', undefined), /valid JSON/);
  assert.throws(() => parseTargets(JSON.stringify({ bad: { ...first, hostKeySha256: '' } }), undefined));
  assert.throws(() => parseTargets(JSON.stringify({ bad: { ...first, password: 'secret' } }), undefined), /exactly one/);
  assert.throws(() => parseTargets(JSON.stringify({ 'invalid.name': first }), undefined), /name/);
  assert.throws(() => parseTargets(JSON.stringify({ typo: { ...first, hostKeySha265: digest } }), undefined), /Unknown SSH target field: hostKeySha265/);
  assert.throws(() => parseTargets(JSON.stringify({ typo: { ...first, passwrod: 'secret' } }), undefined), /Unknown SSH target field: passwrod/);
});
