import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Client } from 'ssh2';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHostKeyVerifier } from '../build/ssh/host-key.js';
import { uploadFile, downloadFile } from '../build/ssh/sftp-transfer.js';

const host = process.env.SSH_INTEGRATION_HOST;
const port = Number(process.env.SSH_INTEGRATION_PORT || 0);
const username = process.env.SSH_INTEGRATION_USER;
const privateKeyPath = process.env.SSH_INTEGRATION_KEY;
const hostKeyHex = process.env.SSH_INTEGRATION_HOST_KEY_HEX;
const enabled = Boolean(host && port && username && privateKeyPath && hostKeyHex);

function connect(privateKey, verifier) {
  return new Promise((resolve, reject) => {
    const client = new Client();
    client.once('ready', () => resolve(client));
    client.once('error', reject);
    client.connect({
      host, port, username, privateKey, readyTimeout: 5000,
      hostHash: 'sha256', hostVerifier: verifier,
    });
  });
}

function openSftp(client) {
  return new Promise((resolve, reject) => client.sftp((err, sftp) => err ? reject(err) : resolve(sftp)));
}

function exec(client, command) {
  return new Promise((resolve, reject) => client.exec(command, (error, stream) => {
    if (error) return reject(error);
    let stdout = '';
    stream.on('data', chunk => { stdout += chunk.toString(); });
    stream.on('close', code => code === 0 ? resolve(stdout) : reject(new Error('exit ' + code)));
    stream.on('error', reject);
  }));
}

test('real SSH: pinned host key, authentication, exec and SFTP round trip', { skip: !enabled }, async () => {
  const privateKey = await readFile(privateKeyPath);
  const verify = createHostKeyVerifier(hostKeyHex);
  const client = await connect(privateKey, verify);
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-integration-'));
  try {
    assert.match(await exec(client, 'printf integration-ok'), /integration-ok/);
    const sftp = await openSftp(client);
    const source = join(dir, 'source.txt');
    const target = join(dir, 'target.txt');
    const remote = '/tmp/ssh-mcp-' + process.pid + '-' + Date.now() + '.txt';
    await writeFile(source, 'integration SFTP content');
    try {
      await uploadFile(sftp, source, remote);
      await downloadFile(sftp, remote, target);
      assert.equal(await readFile(target, 'utf8'), 'integration SFTP content');
    } finally {
      await new Promise(resolve => sftp.unlink(remote, () => resolve()));
    }
  } finally {
    client.end();
    await rm(dir, { recursive: true, force: true });
  }
});

test('real SSH: incorrect host key is rejected', { skip: !enabled }, async () => {
  const privateKey = await readFile(privateKeyPath);
  const incorrect = hostKeyHex.replace(/^./, hostKeyHex[0] === 'a' ? 'b' : 'a');
  await assert.rejects(() => connect(privateKey, createHostKeyVerifier(incorrect)));
});

test('real SSH: SFTP rejects oversized upload and removes staged remote file', { skip: !enabled }, async () => {
  const privateKey = await readFile(privateKeyPath);
  const client = await connect(privateKey, createHostKeyVerifier(hostKeyHex));
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-integration-limit-'));
  const remote = '/tmp/ssh-mcp-limit-' + process.pid + '-' + Date.now() + '.txt';
  try {
    const sftp = await openSftp(client);
    const source = join(dir, 'oversized.txt');
    await writeFile(source, 'larger than four bytes');
    await assert.rejects(() => uploadFile(sftp, source, remote, { maxBytes: 4 }), /size limit/);
    await assert.rejects(() => downloadFile(sftp, remote, join(dir, 'missing.txt')), /No such file|ENOENT|not found/i);
    const files = await new Promise((resolve, reject) => sftp.readdir('/tmp', (err, list) => err ? reject(err) : resolve(list)));
    assert.equal(files.some(entry => entry.filename.startsWith(remote.split('/').at(-1) + '.ssh-mcp-')), false);
  } finally {
    client.end();
    await rm(dir, { recursive: true, force: true });
  }
});

test('real SSH: SFTP upload refuses an existing remote destination', { skip: !enabled }, async () => {
  const privateKey = await readFile(privateKeyPath);
  const client = await connect(privateKey, createHostKeyVerifier(hostKeyHex));
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-integration-existing-'));
  const remote = '/tmp/ssh-mcp-existing-' + process.pid + '-' + Date.now() + '.txt';
  try {
    const sftp = await openSftp(client);
    const source = join(dir, 'source.txt');
    await writeFile(source, 'replacement');
    await new Promise((resolve, reject) => {
      const stream = sftp.createWriteStream(remote, { flags: 'wx' });
      stream.on('error', reject);
      stream.on('close', resolve);
      stream.end('original');
    });
    await assert.rejects(() => uploadFile(sftp, source, remote), /already exists/);
    const target = join(dir, 'target.txt');
    await downloadFile(sftp, remote, target);
    assert.equal(await readFile(target, 'utf8'), 'original');
  } finally {
    const sftp = await openSftp(client);
    await new Promise(resolve => sftp.unlink(remote, () => resolve()));
    client.end();
    await rm(dir, { recursive: true, force: true });
  }
});

test('real SSH: authentication rejects an untrusted private key', { skip: !enabled }, async () => {
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey } = generateKeyPairSync('ed25519');
  const unrelatedKey = privateKey.export({ type: 'pkcs8', format: 'pem' });
  await assert.rejects(
    () => connect(unrelatedKey, createHostKeyVerifier(hostKeyHex)),
    /authentication methods failed|authentication/i,
  );
});
