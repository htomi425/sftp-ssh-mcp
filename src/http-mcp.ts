import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { HttpPrincipal } from './http-access.js';
import { readBoundedJsonBody, HttpBodyTooLargeError, HttpInvalidJsonError } from './http-body.js';
import { parseHttpRequestLimits } from './http-limits.js';

export interface HttpMcpServer {
  connect(transport: StreamableHTTPServerTransport): Promise<void>;
  close(): Promise<void>;
}

export type HttpMcpServerFactory = (principal: HttpPrincipal) => HttpMcpServer;

/**
 * Stateless MCP transport: a fresh server and transport for every request.
 * The principal is captured in the request-local factory, never in global
 * mutable state or in a session shared across authenticated callers.
 */
export function createStreamableHttpHandler(factory: HttpMcpServerFactory) {
  const { maxBodyBytes } = parseHttpRequestLimits(process.env);
  return async ({ principal, request, response }: {
    principal: HttpPrincipal;
    request: IncomingMessage;
    response: ServerResponse;
  }): Promise<void> => {
    let parsedBody: unknown;
    if (request.method === 'POST') {
      try {
        parsedBody = await readBoundedJsonBody(request, maxBodyBytes);
      } catch (error) {
        if (!response.headersSent) response.writeHead(error instanceof HttpBodyTooLargeError ? 413 : error instanceof HttpInvalidJsonError ? 400 : 500).end();
        return;
      }
    }
    const server = factory(principal);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    try {
      await server.connect(transport);
      await transport.handleRequest(request, response, parsedBody);
    } finally {
      await transport.close();
      await server.close();
    }
  };
}
