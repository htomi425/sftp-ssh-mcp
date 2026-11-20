export interface HttpRequestGate {
  acquire(): () => void;
}

export function createHttpRequestGate(maxConcurrent: number): HttpRequestGate {
  if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 256) {
    throw new Error('HTTP concurrency limit must be an integer from 1 to 256');
  }
  let active = 0;
  return {
    acquire() {
      if (active >= maxConcurrent) throw new Error('HTTP concurrency limit reached');
      active++;
      let released = false;
      return () => {
        if (!released) {
          released = true;
          active--;
        }
      };
    },
  };
}

export function parseHttpRequestLimits(env: Record<string, string | undefined>) {
  function bounded(name: string, fallback: number, min: number, max: number) {
    const raw = env[name];
    if (raw === undefined) return fallback;
    if (!/^[0-9]+$/.test(raw)) throw new Error(name + ' must be an integer');
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value < min || value > max) {
      throw new Error(name + ' must be between ' + min + ' and ' + max);
    }
    return value;
  }
  return {
    maxBodyBytes: bounded('SSH_MCP_HTTP_MAX_BODY_BYTES', 1024 * 1024, 1024, 16 * 1024 * 1024),
    maxConcurrent: bounded('SSH_MCP_HTTP_MAX_REQUESTS', 8, 1, 256),
    requestTimeoutMs: bounded('SSH_MCP_HTTP_REQUEST_TIMEOUT_MS', 120000, 1000, 600000),
  };
}
