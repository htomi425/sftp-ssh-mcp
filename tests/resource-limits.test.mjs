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

test('connection gate rejects excess parallel operations and recovers all slots', async () => {
  const gate = new ConnectionGate(2);
  const first = gate.acquire();
  const second = gate.acquire();
  assert.equal(gate.activeCount, 2);
  for (let i = 0; i < 10; i++) assert.throws(() => gate.acquire(), /limit/);
  first();
  const third = gate.acquire();
  assert.equal(gate.activeCount, 2);
  second();
  third();
  assert.equal(gate.activeCount, 0);
  assert.equal(typeof gate.acquire(), 'function');
});
