import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseTargets, selectTarget, sshConfigForTarget } from '../build/ssh/targets.js';

const digest = 'a'.repeat(64);
const first = { host: '127.0.0.1', user: 'alice', key: '/tmp/alice', hostKeySha256: digest };
const second = { host: '192.0.2.10', user: 'bob', password: 'test', hostKeySha256: 'b'.repeat(64) };

test('legacy configuration becomes default target', () => {
  const targets = parseTargets(undefined, first);
  assert.equal(selectTarget(targets).user, 'alice');
});
test('multiple named targets require explicit selection', () => {
  const targets = parseTargets(JSON.stringify({ alpha: first, beta: second }), undefined);
  assert.equal(selectTarget(targets, 'beta').user, 'bob');
  assert.throws(() => selectTarget(targets), /ambiguous/);
  assert.throws(() => selectTarget(targets, 'missing'), /Unknown/);
});
test('rejects malformed or insecure target configuration', () => {
  assert.throws(() => parseTargets('{', undefined), /valid JSON/);
  assert.throws(() => parseTargets(JSON.stringify({ bad: { ...first, hostKeySha256: '' } }), undefined));
  assert.throws(() => parseTargets(JSON.stringify({ bad: { ...first, password: 'secret' } }), undefined), /exactly one/);
  assert.throws(() => parseTargets(JSON.stringify({ 'invalid.name': first }), undefined), { message: 'Invalid SSH target name' });
  assert.throws(() => parseTargets(JSON.stringify({ typo: { ...first, hostKeySha265: digest } }), undefined), { message: 'Unknown SSH target field' });
  assert.throws(() => parseTargets(JSON.stringify({ typo: { ...first, passwrod: 'secret' } }), undefined), { message: 'Unknown SSH target field' });
});

test('HTTP reads private keys only from service-owned private regular files on POSIX', {
  skip: process.geteuid === undefined,
}, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-keys-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const key = join(dir, 'key');
  const target = { ...first, key };
  const unavailable = { message: 'SSH private key is unavailable' };
  await writeFile(key, 'test key', { mode: 0o600 });
  assert.equal((await sshConfigForTarget(target, 'http')).privateKey, 'test key');

  const link = join(dir, 'link');
  await symlink(key, link);
  await assert.rejects(sshConfigForTarget({ ...target, key: link }, 'http'), unavailable);
  const directory = join(dir, 'directory');
  await mkdir(directory, { mode: 0o700 });
  await assert.rejects(sshConfigForTarget({ ...target, key: directory }, 'http'), unavailable);

  await chmod(key, 0o644);
  await assert.rejects(sshConfigForTarget(target, 'http'), unavailable);
  assert.equal((await sshConfigForTarget(target)).privateKey, 'test key');
});
