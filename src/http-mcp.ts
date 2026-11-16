import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { HttpPrincipal } from './http-access.js';
import { readBoundedJsonBody, HttpBodyTooLargeError, HttpInvalidJsonError } from './http-body.js';
import { parseHttpRequestLimits } from './http-limits.js';

export interface HttpMcpServer {
  connect(transport: StreamableHTTPServerTransport): Promise<void>;
  close(): Promise<void>;
}

export type HttpMcpServerFactory = (principal: HttpPrincipal, signal?: AbortSignal) => HttpMcpServer;

/**
 * Stateless MCP transport: a fresh server and transport for every request.
 * The principal is captured in the request-local factory, never in global
 * mutable state or in a session shared across authenticated callers.
 */
export function createStreamableHttpHandler(factory: HttpMcpServerFactory) {
  const { maxBodyBytes } = parseHttpRequestLimits(process.env);
  return async ({ principal, request, response, parsedBody: preauthenticatedBody, signal }: {
    principal: HttpPrincipal;
    request: IncomingMessage;
    response: ServerResponse;
    parsedBody?: unknown;
    signal?: AbortSignal;
  }): Promise<void> => {
    let parsedBody: unknown = preauthenticatedBody;
    if (request.method === 'POST' && preauthenticatedBody === undefined) {
      try {
        parsedBody = await readBoundedJsonBody(request, maxBodyBytes);
      } catch (error) {
        if (!response.headersSent) response.writeHead(error instanceof HttpBodyTooLargeError ? 413 : error instanceof HttpInvalidJsonError ? 400 : 500).end();
        return;
      }
    }
    signal?.throwIfAborted();
    const server = factory(principal, signal);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    let closing: Promise<void> | undefined;
    const close = () => closing ??= Promise.allSettled([transport.close(), server.close()]).then(() => undefined);
    const abort = () => { void close(); };
    signal?.addEventListener('abort', abort, { once: true });
    try {
      signal?.throwIfAborted();
      await server.connect(transport);
      signal?.throwIfAborted();
      await transport.handleRequest(request, response, parsedBody);
    } finally {
      signal?.removeEventListener('abort', abort);
      await close();
    }
  };
}
