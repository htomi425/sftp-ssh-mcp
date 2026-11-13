import type { IncomingMessage } from 'node:http';

export class HttpBodyTooLargeError extends Error {
  constructor() { super('HTTP request body exceeds configured limit'); }
}

export class HttpInvalidJsonError extends Error {
  constructor() { super('Invalid JSON request body'); }
}

/**
 * Read a bounded body once. The MCP SDK receives parsedBody and must not
 * independently consume the already-drained request stream.
 */
export async function readBoundedJsonBody(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > maxBytes) throw new HttpBodyTooLargeError();
    chunks.push(bytes);
  }
  try {
    return JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
  } catch {
    throw new HttpInvalidJsonError();
  }
}
