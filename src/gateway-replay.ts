import type { GatewayAssertionVerifier } from './gateway-assertion.js';
import type { VerifiedIdentity } from './identity-target-policy.js';

export interface ReplayProtectedGatewayVerifier {
  verifyOnce(token: string, nowSeconds?: number): VerifiedIdentity;
}

export interface ReplayCache {
  claim(jti: string, expiresAtSeconds: number, nowSeconds: number): boolean;
}

/**
 * Process-local replay cache. Suitable only for a single Node.js process.
 * Multi-instance deployments MUST use an atomic shared store.
 */
export function createInMemoryReplayCache(maxEntries = 10000): ReplayCache {
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 1000000) throw new Error('Invalid replay cache capacity');
  const seen = new Map<string, number>();
  return {
    claim(jti, expiresAtSeconds, nowSeconds) {
      if (typeof jti !== 'string' || !jti || !Number.isSafeInteger(expiresAtSeconds) || !Number.isSafeInteger(nowSeconds) || expiresAtSeconds <= nowSeconds) return false;
      for (const [key, expiry] of seen) if (expiry <= nowSeconds) seen.delete(key);
      if (seen.has(jti) || seen.size >= maxEntries) return false;
      seen.set(jti, expiresAtSeconds);
      return true;
    },
  };
}

/**
 * A verified assertion is consumed once. The caller MUST ensure a single
 * atomic replay cache is shared by all requests handled by this process.
 * This is not a request-binding mechanism.
 */
export function createReplayProtectedGatewayVerifier(
  verifier: GatewayAssertionVerifier,
  cache: ReplayCache,
): ReplayProtectedGatewayVerifier {
  return {
    verifyOnce(token, nowSeconds = Math.floor(Date.now() / 1000)) {
      const identity = verifier.verify(token, nowSeconds);
      const parts = token.split('.');
      if (parts.length !== 3) throw new Error('Invalid gateway assertion');
      let claims: unknown;
      try { claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); }
      catch { throw new Error('Invalid gateway assertion claims'); }
      if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw new Error('Invalid gateway assertion claims');
      const { jti, exp } = claims as Record<string, unknown>;
      if (typeof jti !== 'string' || typeof exp !== 'number' || !cache.claim(jti, exp, nowSeconds)) {
        throw new Error('Gateway assertion replayed or replay cache unavailable');
      }
      return identity;
    },
  };
}
