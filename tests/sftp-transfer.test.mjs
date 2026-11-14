import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { uploadFile, downloadFile } from '../build/ssh/sftp-transfer.js';

test('upload streams a local file to SFTP', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-upload-'));
  try {
    const local = join(dir, 'source.txt');
    await writeFile(local, 'streamed upload');
    const chunks = [];
    const renamed = [];
    const sftp = {
      stat: (_path, cb) => cb(Object.assign(new Error('not found'), { code: 2 })),
      rename: (from, to, cb) => { renamed.push([from, to]); cb(null); },
      unlink: (_path, cb) => cb(null),
      createWriteStream: () => new Writable({
        write(chunk, encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); },
      }),
    };
    await uploadFile(sftp, local, '/remote.txt');
    assert.equal(Buffer.concat(chunks).toString(), 'streamed upload');
    assert.equal(renamed.length, 1);
    assert.equal(renamed[0][1], '/remote.txt');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('download streams SFTP data into a new local file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-download-'));
  try {
    const local = join(dir, 'download.txt');
    const sftp = { createReadStream: () => Readable.from(['streamed ', 'download']) };
    await downloadFile(sftp, '/remote.txt', local);
    assert.equal(await readFile(local, 'utf8'), 'streamed download');
    await assert.rejects(() => downloadFile(sftp, '/remote.txt', local), /EEXIST/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('upload rejects data exceeding transfer size limit', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-limit-'));
  try {
    const local = join(dir, 'source.txt');
    await writeFile(local, 'too many bytes');
    let cleaned = false;
    const sftp = {
      stat: (_path, cb) => cb(Object.assign(new Error('not found'), { code: 2 })),
      unlink: (_path, cb) => { cleaned = true; cb(null); },
      rename: (_from, _to, cb) => cb(null),
      createWriteStream: () => new Writable({ write(_chunk, _enc, callback) { callback(); } }),
    };
    await assert.rejects(() => uploadFile(sftp, local, '/remote.txt', { maxBytes: 4 }), /size limit/);
    assert.equal(cleaned, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('download rejects excess bytes without leaving a partial destination', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-partial-'));
  try {
    const local = join(dir, 'download.txt');
    const sftp = { createReadStream: () => Readable.from(['longer than limit']) };
    await assert.rejects(() => downloadFile(sftp, '/remote.txt', local, { maxBytes: 4 }), /size limit/);
    await assert.rejects(() => readFile(local), /ENOENT/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('upload aborts a stalled SFTP destination on timeout and requests cleanup', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-timeout-'));
  try {
    const local = join(dir, 'source.txt');
    await writeFile(local, Buffer.alloc(128 * 1024, 65));
    let removed = false;
    const sftp = {
      stat: (_path, cb) => cb(Object.assign(new Error('not found'), { code: 2 })),
      unlink: (_path, cb) => { removed = true; cb(null); },
      createWriteStream: () => new Writable({
        highWaterMark: 1,
        write(_chunk, _encoding, _callback) { /* simulate stalled network */ },
      }),
    };
    await assert.rejects(() => uploadFile(sftp, local, '/remote.txt', { timeoutMs: 1000 }), /abort|timeout/i);
    assert.equal(removed, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
