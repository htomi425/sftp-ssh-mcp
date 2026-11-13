import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { HttpAccessPolicy, HttpPrincipal } from './http-access.js';

export interface HttpRequestContext {
  principal: HttpPrincipal;
  request: IncomingMessage;
  response: ServerResponse;
}

export type AuthorizedMcpHandler = (context: HttpRequestContext) => Promise<void>;

/**
 * Authentication boundary for the eventual Streamable HTTP transport.
 * The handler is invoked only after authentication; target-level authorization
 * must additionally be checked by the MCP tool implementation.
 */
export function createAuthenticatedHttpServer(policy: HttpAccessPolicy, handler: AuthorizedMcpHandler) {
  return createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.url !== '/mcp' || !['POST', 'GET', 'DELETE'].includes(request.method ?? '')) {
      response.writeHead(404).end();
      return;
    }
    let principal: HttpPrincipal;
    try {
      const authorization = request.headers.authorization;
      principal = policy.authenticate(authorization);
    } catch {
      response.setHeader('WWW-Authenticate', 'Bearer');
      response.writeHead(401).end();
      return;
    }
    try {
      await handler({ principal, request, response });
    } catch {
      if (!response.headersSent) response.writeHead(500).end();
      else response.destroy();
    }
  });
}

export async function listenLoopback(server: ReturnType<typeof createAuthenticatedHttpServer>, host: string, port: number): Promise<AddressInfo> {
  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) throw new Error('HTTP listener must bind to loopback');
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve(server.address() as AddressInfo);
    });
  });
}
