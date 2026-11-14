import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatCommandResult } from '../build/ssh/command-result.js';
import { formatDirectoryListing } from '../build/ssh/directory-listing.js';

test('directory listing formats entries', () => {
  assert.equal(formatDirectoryListing([{ filename: 'a', longname: '-rw-r--r-- a' }]), 'a (-rw-r--r-- a)');
});
test('empty directory listing', () => {
  assert.equal(formatDirectoryListing([]), '');
});
test('successful command may write to stderr', () => {
  assert.equal(formatCommandResult({ stdout: 'ok', stderr: 'warning', exitCode: 0 }), 'ok\n[stderr]\nwarning');
});
test('nonzero exit status is an error', () => {
  assert.throws(() => formatCommandResult({ stdout: '', stderr: 'failure', exitCode: 1 }), /exit 1/);
});
test('missing exit status is not treated as success', () => {
  assert.throws(() => formatCommandResult({ stdout: '', stderr: '', exitCode: null, signal: 'TERM' }), /signal TERM/);
});
