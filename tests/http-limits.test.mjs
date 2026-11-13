import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHttpRequestGate, parseHttpRequestLimits } from '../build/http-limits.js';

test('HTTP request limit settings use bounded defaults and reject unsafe values', () => {
  assert.deepEqual(parseHttpRequestLimits({}), {
    maxBodyBytes: 1048576,
    maxConcurrent: 8,
    requestTimeoutMs: 120000,
  });
  assert.throws(() => parseHttpRequestLimits({ SSH_MCP_HTTP_MAX_BODY_BYTES: '0' }));
  assert.throws(() => parseHttpRequestLimits({ SSH_MCP_HTTP_MAX_REQUESTS: '257' }));
  assert.throws(() => parseHttpRequestLimits({ SSH_MCP_HTTP_REQUEST_TIMEOUT_MS: '-1' }));
});

test('HTTP request concurrency gate rejects overflow and releases once', () => {
  const gate = createHttpRequestGate(1);
  const release = gate.acquire();
  assert.throws(() => gate.acquire(), /concurrency limit/);
  release();
  release();
  const next = gate.acquire();
  next();
});
