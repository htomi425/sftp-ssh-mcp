import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DEFAULT_EXEC_TIMEOUT_MS, DEFAULT_MAX_OUTPUT_BYTES, OutputLimiter, validateExecLimits } from '../build/ssh/exec-limits.js';

test('defaults are within allowed bounds', () => {
  assert.doesNotThrow(() => validateExecLimits(DEFAULT_EXEC_TIMEOUT_MS, DEFAULT_MAX_OUTPUT_BYTES));
});
test('invalid timeouts are rejected', () => {
  for (const n of [0, 999, 300001, NaN, 1.5]) {
    assert.throws(() => validateExecLimits(n, DEFAULT_MAX_OUTPUT_BYTES), /timeout/);
  }
});
test('invalid output limits are rejected', () => {
  for (const n of [0, 1023, 16777217, NaN, 1.5]) {
    assert.throws(() => validateExecLimits(DEFAULT_EXEC_TIMEOUT_MS, n), /output/);
  }
});
test('output budget accumulates across stdout and stderr', () => {
  const limit = new OutputLimiter(5);
  limit.add(Buffer.from('abc'));
  limit.add(Buffer.from('de'));
  assert.equal(limit.usedBytes, 5);
  assert.throws(() => limit.add(Buffer.from('f')), /exceeded/);
});
test('output budget measures bytes, not Unicode characters', () => {
  const limit = new OutputLimiter(3);
  limit.add(Buffer.from('あ'));
  assert.throws(() => limit.add(Buffer.from('x')), /exceeded/);
});
