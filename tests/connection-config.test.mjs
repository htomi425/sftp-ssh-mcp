import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateConnectionOptions } from '../build/ssh/connection-config.js';

const valid = { host: 'example.org', username: 'tester', port: 22, readyTimeout: 10000 };

test('accepts valid SSH options', () => {
  assert.deepEqual(validateConnectionOptions(valid), valid);
});
test('rejects missing SSH host', () => {
  assert.throws(() => validateConnectionOptions({ ...valid, host: ' ' }), /host/);
});
test('rejects missing SSH user', () => {
  assert.throws(() => validateConnectionOptions({ ...valid, username: '' }), /username/);
});
test('rejects invalid port values', () => {
  for (const port of [0, -1, 65536, 22.5, Number.NaN]) {
    assert.throws(() => validateConnectionOptions({ ...valid, port }), /port/);
  }
});
test('rejects invalid connection timeout', () => {
  for (const readyTimeout of [0, 999, 120001, Number.NaN]) {
    assert.throws(() => validateConnectionOptions({ ...valid, readyTimeout }), /readyTimeout/);
  }
});
