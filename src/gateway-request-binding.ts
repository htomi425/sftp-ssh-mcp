import { createHash, timingSafeEqual } from 'node:crypto';
import type { GatewayAssertionVerifier } from './gateway-assertion.js';
import type { VerifiedIdentity } from './identity-target-policy.js';
import type { ReplayCache } from './gateway-replay.js';

export interface GatewayRequestBinding {
  method: 'POST' | 'GET' | 'DELETE';
  path: '/mcp';
  /** Raw request bytes, before JSON parsing or transformation. */
  body: Buffer;
}

const B64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Verify signature, signed method/path/body digest and single-use jti.
 * The gateway MUST sign the exact bytes forwarded to the origin.
 * Call before dispatching any MCP operation. This is not an OAuth verifier.
 */
export function createRequestBoundGatewayVerifier(verifier: GatewayAssertionVerifier, replay: ReplayCache) {
  return {
    verifyOnce(token: string, request: GatewayRequestBinding, nowSeconds = Math.floor(Date.now() / 1000)): VerifiedIdentity {
      const identity = verifier.verify(token, nowSeconds);
      const parts = token.split('.');
      if (parts.length !== 3 || !B64URL.test(parts[1])) throw new Error('Invalid gateway assertion payload');
      const bytes = Buffer.from(parts[1], 'base64url');
      if (bytes.toString('base64url') !== parts[1]) throw new Error('Invalid gateway assertion payload');
      let value: unknown;
      try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('Invalid gateway assertion payload'); }
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid gateway assertion payload');
      const claims = value as Record<string, unknown>;
      if (claims.htm !== request.method || claims.htu !== request.path ||
          typeof claims.body_sha256 !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(claims.body_sha256)) {
        throw new Error('Gateway assertion request binding mismatch');
      }
      const expected = createHash('sha256').update(request.body).digest();
      const provided = Buffer.from(claims.body_sha256, 'base64url');
      if (provided.length !== expected.length || provided.toString('base64url') !== claims.body_sha256 ||
          !timingSafeEqual(expected, provided)) {
        throw new Error('Gateway assertion body digest mismatch');
      }
      if (typeof claims.jti !== 'string' || typeof claims.exp !== 'number' ||
          !replay.claim(claims.iss + '\0' + claims.jti, claims.exp, nowSeconds)) {
        throw new Error('Gateway assertion replayed or replay cache unavailable');
      }
      return identity;
    },
  };
}
