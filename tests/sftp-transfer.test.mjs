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
