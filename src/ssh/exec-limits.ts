export const DEFAULT_EXEC_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;

export function validateExecLimits(timeoutMs: number, maxOutputBytes: number): void {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 300_000) {
    throw new Error('Command timeout must be between 1000 and 300000 ms');
  }
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1024 || maxOutputBytes > 16_777_216) {
    throw new Error('Command output limit must be between 1024 and 16777216 bytes');
  }
}

export class OutputLimiter {
  private bytes = 0;
  constructor(private readonly maxBytes: number) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error('Invalid output limit');
  }
  add(chunk: Buffer): void {
    this.bytes += chunk.byteLength;
    if (this.bytes > this.maxBytes) throw new Error('SSH command output exceeded byte limit');
  }
  get usedBytes(): number { return this.bytes; }
}
