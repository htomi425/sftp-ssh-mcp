import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveToolTarget } from '../build/tool-target.js';

const registry = {
  default: { host: '127.0.0.1', user: 'root', password: 'example', hostKeySha256: 'a'.repeat(64) },
  restricted: { host: '127.0.0.2', user: 'root', password: 'example', hostKeySha256: 'b'.repeat(64) },
};
const principal = { id: 'limited', targets: new Set(['restricted']) };

test('stdio target resolution retains legacy default and explicit selection', () => {
  assert.equal(resolveToolTarget(registry, undefined, {}, 'stdio'), registry.default);
  assert.equal(resolveToolTarget(registry, 'restricted', {}, 'stdio'), registry.restricted);
  assert.throws(() => resolveToolTarget(registry, undefined, { principal }, 'stdio'), /cannot be used/);
});

test('HTTP target resolution never runs without principal or accesses unauthorized default', () => {
  assert.throws(() => resolveToolTarget(registry, 'default', {}, 'http'), /authenticated principal/);
  assert.equal(resolveToolTarget(registry, undefined, { principal }, 'http'), registry.restricted);
  assert.throws(() => resolveToolTarget(registry, 'default', { principal }, 'http'), /denied/);
  assert.throws(() => resolveToolTarget(registry, 'unknown', { principal }, 'http'), /denied/);
});
