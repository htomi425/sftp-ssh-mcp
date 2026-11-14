import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Readable } from 'node:stream';
import { readBoundedJsonBody, HttpBodyTooLargeError, HttpInvalidJsonError } from '../build/http-body.js';

test('bounded body parses JSON spread across multiple chunks', async () => {
  const stream = Readable.from([Buffer.from('{"json'), Buffer.from('rpc":"2.0"}')]);
  assert.deepEqual(await readBoundedJsonBody(stream, 64), { jsonrpc: '2.0' });
});

test('bounded body rejects oversized chunked payload without Content-Length', async () => {
  const stream = Readable.from([Buffer.from('{"a":"'), Buffer.alloc(100, 97), Buffer.from('"}')]);
  await assert.rejects(readBoundedJsonBody(stream, 32), HttpBodyTooLargeError);
});

test('bounded body rejects malformed JSON', async () => {
  await assert.rejects(readBoundedJsonBody(Readable.from([Buffer.from('{')]), 32), HttpInvalidJsonError);
});
