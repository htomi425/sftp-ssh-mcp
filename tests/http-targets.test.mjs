import assert from 'node:assert/strict';
import { test } from 'node:test';
import { selectAuthorizedTarget } from '../build/http-targets.js';
import { parseHttpAccessPolicy } from '../build/http-access.js';

const registry = {
  default: { host: '127.0.0.1', user: 'root', password: 'example', hostKeySha256: 'a'.repeat(64) },
  alpha: { host: '127.0.0.2', user: 'root', password: 'example', hostKeySha256: 'b'.repeat(64) },
  beta: { host: '127.0.0.3', user: 'root', password: 'example', hostKeySha256: 'c'.repeat(64) },
};
const token = 'x'.repeat(48);
function principal(targets) {
  const policy = parseHttpAccessPolicy(JSON.stringify([{ id: 'tester', token, targets }]), new Set(Object.keys(registry)));
  return policy.authenticate('Bearer ' + token);
}

test('HTTP target resolution enforces explicit principal authorization', () => {
  const alice = principal(['alpha']);
  assert.equal(selectAuthorizedTarget(registry, alice).name, 'alpha');
  assert.equal(selectAuthorizedTarget(registry, alice, 'alpha').target.host, '127.0.0.2');
  for (const target of ['default', 'beta', 'missing']) {
    assert.throws(() => selectAuthorizedTarget(registry, alice, target), /denied/);
  }
});
test('HTTP target resolution prefers authorized default, never global default', () => {
  assert.equal(selectAuthorizedTarget(registry, principal(['alpha', 'default'])).name, 'default');
  assert.throws(() => selectAuthorizedTarget(registry, principal(['alpha', 'beta'])), /denied/);
  assert.throws(() => selectAuthorizedTarget(registry, principal(['alpha']), ''), /Invalid/);
});
