export const DEFAULT_MAX_TRANSFER_BYTES = 64 * 1024 * 1024;
export const DEFAULT_TRANSFER_TIMEOUT_MS = 120_000;
export const DEFAULT_MAX_CONCURRENT_CONNECTIONS = 2;

export function parseBoundedInteger(value: string | undefined, fallback: number, min: number, max: number, name: string): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return n;
}

export class ConnectionGate {
  private active = 0;
  constructor(readonly maxConcurrent: number) {
    if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1) {
      throw new Error('maxConcurrent must be a positive integer');
    }
  }
  acquire(): () => void {
    if (this.active >= this.maxConcurrent) throw new Error('SSH connection limit reached');
    this.active++;
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.active--;
      }
    };
  }
  get activeCount(): number { return this.active; }
}
