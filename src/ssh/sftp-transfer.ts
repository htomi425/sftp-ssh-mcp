import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import type { SFTPWrapper } from 'ssh2';

export async function uploadFile(sftp: SFTPWrapper, localPath: string, remotePath: string): Promise<void> {
  await pipeline(createReadStream(localPath), sftp.createWriteStream(remotePath));
}

export async function downloadFile(sftp: SFTPWrapper, remotePath: string, localPath: string): Promise<void> {
  await pipeline(sftp.createReadStream(remotePath), createWriteStream(localPath, { flags: 'wx' }));
}
