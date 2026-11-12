import { createReadStream, createWriteStream } from 'node:fs';
import { unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { link } from 'node:fs/promises';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { SFTPWrapper } from 'ssh2';
import { DEFAULT_MAX_TRANSFER_BYTES, DEFAULT_TRANSFER_TIMEOUT_MS } from './resource-limits.js';

export interface TransferOptions {
  maxBytes?: number;
  timeoutMs?: number;
}

export function byteLimitTransform(maxBytes: number): Transform {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error('Invalid transfer byte limit');
  let total = 0;
  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      total += chunk.byteLength;
      if (total > maxBytes) callback(new Error('SFTP transfer size limit exceeded'));
      else callback(null, chunk);
    },
  });
}

async function boundedPipeline(source: NodeJS.ReadableStream, destination: NodeJS.WritableStream, options: TransferOptions): Promise<void> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_TRANSFER_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TRANSFER_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 600_000) throw new Error('Invalid transfer timeout');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('SFTP transfer timed out')), timeoutMs);
  try {
    await pipeline(source, byteLimitTransform(maxBytes), destination, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function sftpRename(sftp: SFTPWrapper, from: string, to: string): Promise<void> {
  return new Promise((resolve, reject) => sftp.rename(from, to, (error) => error ? reject(error) : resolve()));
}

function sftpUnlink(sftp: SFTPWrapper, path: string): Promise<void> {
  return new Promise((resolve, reject) => sftp.unlink(path, (error) => error ? reject(error) : resolve()));
}

function sftpStat(sftp: SFTPWrapper, path: string): Promise<boolean> {
  return new Promise((resolve, reject) => sftp.stat(path, (error) => {
    if (!error) return resolve(true);
    if ((error as NodeJS.ErrnoException).code === 'ENOENT' || (error as { code?: number }).code === 2) return resolve(false);
    reject(error);
  }));
}

export async function uploadFile(sftp: SFTPWrapper, localPath: string, remotePath: string, options: TransferOptions = {}): Promise<void> {
  // Upload to a sibling path first, so a failed transfer never leaves a partial final file.
  const tempPath = `${remotePath}.ssh-mcp-${randomUUID()}.part`;
  let created = false;
  try {
    if (await sftpStat(sftp, remotePath)) throw new Error('Remote destination already exists');
    created = true;
    await boundedPipeline(createReadStream(localPath), sftp.createWriteStream(tempPath, { flags: 'wx' }), options);
    // Standard SFTP rename may replace a file created concurrently. Enforce exclusive
    // publishing with a server-specific extension before enabling untrusted writers.
    if (await sftpStat(sftp, remotePath)) throw new Error('Remote destination already exists');
    await sftpRename(sftp, tempPath, remotePath);
    created = false;
  } finally {
    if (created) await sftpUnlink(sftp, tempPath).catch(() => undefined);
  }
}

export async function downloadFile(sftp: SFTPWrapper, remotePath: string, localPath: string, options: TransferOptions = {}): Promise<void> {
  // Download into a unique temporary file. An atomic hard link protects existing destinations.
  const tempPath = `${localPath}.ssh-mcp-${randomUUID()}.part`;
  try {
    await boundedPipeline(sftp.createReadStream(remotePath), createWriteStream(tempPath, { flags: 'wx', mode: 0o600 }), options);
    await link(tempPath, localPath);
  } finally {
    await unlink(tempPath).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
    });
  }
}
