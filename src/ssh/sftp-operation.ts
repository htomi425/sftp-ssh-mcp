import { Client, type ConnectConfig } from 'ssh2';
import { ConnectionGate } from './resource-limits.js';

/** Own the connection and its gate slot for the entire operation, including cleanup. */
export function runSftpOperation<T>(
  config: ConnectConfig,
  gate: ConnectionGate,
  timeoutMs: number,
  operation: (client: Client) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (signal?.aborted) return Promise.reject(signal.reason ?? new Error('SSH operation aborted'));
  let release: () => void;
  try { release = gate.acquire(); } catch (error) { return Promise.reject(error); }
  return new Promise<T>((resolve, reject) => {
    const client = new Client();
    let settled = false;
    const timer = setTimeout(() => finish(new Error('SFTP operation timed out')), timeoutMs);
    const abort = () => finish(signal?.reason ?? new Error('SSH operation aborted'));
    function finish(error?: unknown, result?: T) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      // Force teardown: a peer that ignores SFTP requests may also ignore graceful close.
      client.destroy();
      release();
      if (error !== undefined) reject(error);
      else resolve(result as T);
    }
    client.on('error', error => finish(error));
    client.once('close', () => finish(new Error('SSH connection closed before SFTP completed')));
    client.once('ready', () => {
      if (settled) return;
      Promise.resolve().then(() => {
        if (settled) throw new Error('SSH operation aborted');
        return operation(client);
      }).then(result => finish(undefined, result), error => finish(error));
    });
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { abort(); return; }
    try { client.connect(config); } catch (error) { finish(error); }
  });
}
