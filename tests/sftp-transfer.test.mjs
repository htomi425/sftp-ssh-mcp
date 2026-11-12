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
    const sftp = {
      createWriteStream: () => new Writable({
        write(chunk, encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); },
      }),
    };
    await uploadFile(sftp, local, '/remote.txt');
    assert.equal(Buffer.concat(chunks).toString(), 'streamed upload');
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
    const sftp = { createWriteStream: () => new Writable({ write(_chunk, _enc, callback) { callback(); } }) };
    await assert.rejects(() => uploadFile(sftp, local, '/remote.txt', { maxBytes: 4 }), /size limit/);
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
