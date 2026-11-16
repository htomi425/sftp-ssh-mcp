import { constants, openSync, fstatSync, readFileSync, closeSync, lstatSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';

const MAX_LOCK_BYTES = 10 * 1024 * 1024;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function readLockfile(path) {
  if (lstatSync(path).isSymbolicLink()) throw new Error('Lockfile must not be a symbolic link');
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = fstatSync(descriptor);
    if (!info.isFile() || info.size > MAX_LOCK_BYTES) throw new Error('Invalid lockfile type or size');
    const bytes = readFileSync(descriptor);
    if (bytes.length > MAX_LOCK_BYTES) throw new Error('Lockfile exceeds size limit');
    let lock;
    try { lock = JSON.parse(bytes.toString('utf8')); }
    catch { throw new Error('Invalid lockfile JSON'); }
    return { lock, bytes };
  } finally {
    closeSync(descriptor);
  }
}

/** Validate untrusted artifact data without importing or installing any package. */
export function validateLockfile(candidate, baseline) {
  if (!object(candidate) || !object(baseline) ||
      candidate.lockfileVersion !== 3 || baseline.lockfileVersion !== 3 ||
      !object(candidate.packages) || !object(baseline.packages)) {
    throw new Error('Expected a v3 dependency lockfile');
  }
  const metadata = value => Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'packages'));
  if (!isDeepStrictEqual(metadata(candidate), metadata(baseline)) ||
      !Object.hasOwn(candidate.packages, '') ||
      !isDeepStrictEqual(candidate.packages[''], baseline.packages[''])) {
    throw new Error('Candidate changes project or direct dependency metadata');
  }
  let packages = 0;
  for (const [path, entry] of Object.entries(candidate.packages)) {
    if (path === '') continue;
    if (!path.startsWith('node_modules/') || !/^[A-Za-z0-9@_./-]+$/.test(path) ||
        path.split('/').some(part => !part || part === '.' || part === '..') ||
        !object(entry) || entry.link) {
      throw new Error('Unsupported package path or link in candidate');
    }
    if (typeof entry.version !== 'string' || entry.version.length > 256 ||
        !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(entry.version)) {
      throw new Error('Unsupported package version in candidate');
    }
    let url;
    try { url = new URL(entry.resolved); } catch { throw new Error('Invalid registry URL'); }
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' ||
        url.port || url.username || url.password || url.search || url.hash ||
        !url.pathname.endsWith('.tgz')) {
      throw new Error('Candidate must use HTTPS npm registry tarballs');
    }
    if (typeof entry.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity)) {
      throw new Error('Candidate requires SHA-512 integrity');
    }
    const digest = entry.integrity.slice(7);
    const bytes = Buffer.from(digest, 'base64');
    if (bytes.length !== 64 || bytes.toString('base64') !== digest) {
      throw new Error('Invalid SHA-512 integrity encoding');
    }
    packages++;
  }
  if (!packages) throw new Error('Candidate contains no dependencies');
  return packages;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [, , candidatePath, baselinePath] = process.argv;
  if (!candidatePath || !baselinePath) throw new Error('Usage: validate-dependency-lock.mjs CANDIDATE BASELINE');
  const candidate = readLockfile(candidatePath);
  const baseline = readLockfile(baselinePath);
  const packages = validateLockfile(candidate.lock, baseline.lock);
  console.log(JSON.stringify({ packages, sha256: createHash('sha256').update(candidate.bytes).digest('hex') }));
}
