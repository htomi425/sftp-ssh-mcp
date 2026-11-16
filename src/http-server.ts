import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { HttpAccessPolicy, HttpPrincipal } from './http-access.js';
import { HttpBodyTooLargeError } from './http-body.js';
import { createHttpRequestGate, parseHttpRequestLimits } from './http-limits.js';

export interface HttpRequestContext {
  principal: HttpPrincipal;
  request: IncomingMessage;
  response: ServerResponse;
  parsedBody?: unknown;
  signal: AbortSignal;
}

export interface GatewayHttpAuthenticator {
  verifyRequest(token: string, request: { method: 'POST' | 'GET' | 'DELETE'; path: '/mcp'; body: Buffer }): HttpPrincipal;
}

export type AuthorizedMcpHandler = (context: HttpRequestContext) => Promise<void>;

/**
 * Authentication boundary for the eventual Streamable HTTP transport.
 * The handler is invoked only after authentication; target-level authorization
 * must additionally be checked by the MCP tool implementation.
 */
export function createAuthenticatedHttpServer(policy: HttpAccessPolicy | GatewayHttpAuthenticator, handler: AuthorizedMcpHandler) {
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
    const length = request.headers['content-length'];
    if (length !== undefined && (!/^[0-9]+$/.test(length) || Number(length) > limits.maxBodyBytes)) {
      response.writeHead(413).end();
      return;
    }
    let release: () => void;
    try { release = gate.acquire(); } catch { response.writeHead(503).end(); return; }
    const controller = new AbortController();
    const abort = () => controller.abort(new Error('HTTP client disconnected'));
    const responseClosed = () => {
      if (!response.writableFinished) abort();
    };
    request.once('aborted', abort);
    response.once('close', responseClosed);
    const timer = setTimeout(() => {
      controller.abort(new Error('HTTP request execution timed out'));
    }, limits.requestTimeoutMs);
    const cancelled = new Promise<never>((_resolve, reject) => {
      controller.signal.addEventListener('abort', () => reject(controller.signal.reason), { once: true });
    });
    // A cancellation during body reception may precede the race below.
    void cancelled.catch(() => undefined);
    try {
      let principal: HttpPrincipal;
      let parsedBody: unknown;
      if ('verifyRequest' in policy) {
        // Read the raw bytes once, before authentication, so the signed digest
        // covers precisely the bytes passed to the MCP JSON parser.
        let raw = Buffer.alloc(0);
        try {
          const chunks: Buffer[] = [];
          let size = 0;
          await Promise.race([(async () => {
          for await (const chunk of request) {
            const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            size += bytes.length;
            if (size > limits.maxBodyBytes) throw new HttpBodyTooLargeError();
            chunks.push(bytes);
          }
          })(), cancelled]);
          raw = Buffer.concat(chunks, size);
        } catch (error) {
          if (controller.signal.aborted) throw error;
          response.writeHead(error instanceof HttpBodyTooLargeError ? 413 : 400).end();
          return;
        }
        try {
          const authorization = request.headers.authorization;
          const match = typeof authorization === 'string' ? /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.exec(authorization) : null;
          if (!match || match[1].length > 8192) throw new Error('Invalid gateway assertion bearer');
          principal = policy.verifyRequest(match[1], {
            method: request.method as 'POST' | 'GET' | 'DELETE', path: '/mcp', body: raw,
          });
        } catch {
          response.setHeader('WWW-Authenticate', 'Bearer');
          response.writeHead(401).end();
          return;
        }
        if (request.method === 'POST') {
          try { parsedBody = JSON.parse(raw.toString('utf8')); }
          catch { response.writeHead(400).end(); return; }
        }
      } else {
        try { principal = policy.authenticate(request.headers.authorization); }
        catch {
          response.setHeader('WWW-Authenticate', 'Bearer');
          response.writeHead(401).end();
          return;
        }
      }
      controller.signal.throwIfAborted();
      await Promise.race([
        handler({ principal, request, response, parsedBody, signal: controller.signal }),
        cancelled,
      ]);
    } catch {
      if (!response.headersSent && !response.destroyed) response.writeHead(controller.signal.aborted ? 504 : 500).end();
      else response.destroy();
      if (controller.signal.aborted && !request.complete) {
        if (response.writableFinished || response.destroyed) request.destroy();
        else response.once('finish', () => request.destroy());
      }
    } finally {
      clearTimeout(timer);
      request.off('aborted', abort);
      response.off('close', responseClosed);
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
