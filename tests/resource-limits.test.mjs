import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ConnectionGate, parseBoundedInteger } from '../build/ssh/resource-limits.js';

test('bounded integer defaults and validation', () => {
  assert.equal(parseBoundedInteger(undefined, 2, 1, 8, 'limit'), 2);
  assert.equal(parseBoundedInteger('4', 2, 1, 8, 'limit'), 4);
  for (const bad of ['0', '9', '2.5', 'abc', 'Infinity', '']) {
    assert.throws(() => parseBoundedInteger(bad, 2, 1, 8, 'limit'), /limit/);
  }
});
test('connection gate enforces concurrency and releases once', () => {
  const gate = new ConnectionGate(1);
  const release = gate.acquire();
  assert.equal(gate.activeCount, 1);
  assert.throws(() => gate.acquire(), /limit/);
  release();
  release();
  assert.equal(gate.activeCount, 0);
  gate.acquire()();
});
