import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { HttpAccessPolicy, HttpPrincipal } from './http-access.js';
import { createHttpRequestGate, parseHttpRequestLimits } from './http-limits.js';

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
  const limits = parseHttpRequestLimits(process.env);
  const gate = createHttpRequestGate(limits.maxConcurrent);
  const server = createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.url !== '/mcp' || !['POST', 'GET', 'DELETE'].includes(request.method ?? '')) {
      response.writeHead(404).end();
      return;
    }
    // Browser origins are never trusted implicitly; cross-origin requests are denied.
    if (request.headers.origin !== undefined) {
      response.writeHead(403).end();
      return;
    }
    // Refuse ambiguous credentials before inspecting the bearer token.
    if (request.headersDistinct.authorization?.length !== 1) {
      response.setHeader('WWW-Authenticate', 'Bearer');
      response.writeHead(401).end();
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
    const length = request.headers['content-length'];
    if (length !== undefined && (!/^[0-9]+$/.test(length) || Number(length) > limits.maxBodyBytes)) {
      response.writeHead(413).end();
      return;
    }
    let release: () => void;
    try { release = gate.acquire(); } catch { response.writeHead(503).end(); return; }
    let received = 0;
    request.on('data', (chunk: Buffer) => {
      received += chunk.length;
      if (received > limits.maxBodyBytes) {
        if (!response.headersSent) response.writeHead(413).end();
        request.destroy();
      }
    });
    try {
      await handler({ principal, request, response });
    } catch {
      if (!response.headersSent) response.writeHead(500).end();
      else response.destroy();
    } finally {
      release();
    }
  });
  server.requestTimeout = limits.requestTimeoutMs;
  return server;
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
