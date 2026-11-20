import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readLockfile, validateLockfile } from '../scripts/validate-dependency-lock.mjs';

const baseline = {
  name: 'fixture', version: '1.0.0', lockfileVersion: 3, requires: true,
  packages: {
    '': { name: 'fixture', version: '1.0.0', dependencies: { example: '^1.0.0' } },
    'node_modules/example': {
      version: '1.0.0', resolved: 'https://registry.npmjs.org/example/-/example-1.0.0.tgz',
      integrity: 'sha512-' + Buffer.alloc(64, 1).toString('base64'),
    },
  },
};
const candidate = () => structuredClone(baseline);

test('candidate validation accepts registry updates while preserving declared dependency policy', () => {
  const lock = candidate();
  lock.packages['node_modules/example'].version = '1.1.0';
  lock.packages['node_modules/example'].resolved = 'https://registry.npmjs.org/example/-/example-1.1.0.tgz';
  assert.equal(validateLockfile(lock, baseline), 1);
});

test('candidate validation refuses project and direct dependency metadata changes', () => {
  for (const mutate of [
    lock => { lock.name = 'other'; },
    lock => { lock.packages[''].dependencies.example = '*'; },
    lock => { lock.lockfileVersion = 2; },
    lock => { lock.extra = 'unexpected'; },
    lock => { lock.packages = []; },
    lock => { delete lock.packages['']; },
  ]) {
    const lock = candidate(); mutate(lock);
    assert.throws(() => validateLockfile(lock, baseline));
  }
});

test('candidate validation refuses alternate registries, credentials and local or git sources', () => {
  for (const resolved of [
    'https://attacker.example/example.tgz', 'http://registry.npmjs.org/example.tgz',
    'https://user:password@registry.npmjs.org/example.tgz',
    'https://registry.npmjs.org/example.tgz?token=value',
    'file:///tmp/example.tgz', 'git+https://github.com/example/repo.git',
  ]) {
    const lock = candidate(); lock.packages['node_modules/example'].resolved = resolved;
    assert.throws(() => validateLockfile(lock, baseline));
  }
});

test('candidate validation refuses missing integrity, traversal and package links', () => {
  for (const mutate of [
    lock => { delete lock.packages['node_modules/example'].integrity; },
    lock => { lock.packages['node_modules/example'].integrity = 'sha1-weak'; },
    lock => { lock.packages['node_modules/example'].integrity = 'sha512-' + 'A'.repeat(85) + 'B=='; },
    lock => { lock.packages['node_modules/example'].link = true; },
    lock => { lock.packages['node_modules/../escape'] = lock.packages['node_modules/example']; },
    lock => { lock.packages['node_modules/example'].version = 'file:./package'; },
    lock => { delete lock.packages['node_modules/example']; },
  ]) {
    const lock = candidate(); mutate(lock);
    assert.throws(() => validateLockfile(lock, baseline));
  }
});

test('artifact reader rejects malformed JSON and oversized files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dependency-artifact-'));
  try {
    const path = join(dir, 'candidate.json');
    await writeFile(path, '{invalid');
    assert.throws(() => readLockfile(path), /Invalid lockfile JSON/);
    await writeFile(path, Buffer.alloc(10 * 1024 * 1024 + 1));
    assert.throws(() => readLockfile(path), /size/);
    await writeFile(path, JSON.stringify(baseline));
    assert.deepEqual(readLockfile(path).lock, baseline);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('artifact reader refuses symbolic links', { skip: process.platform === 'win32' }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dependency-symlink-'));
  try {
    const path = join(dir, 'candidate.json');
    const link = join(dir, 'linked.json');
    await writeFile(path, JSON.stringify(baseline));
    await symlink(path, link);
    assert.throws(() => readLockfile(link), /symbolic link/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
