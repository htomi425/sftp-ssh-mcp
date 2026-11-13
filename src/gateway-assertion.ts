import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import type { VerifiedIdentity } from './identity-target-policy.js';

export interface GatewayAssertionVerifier {
  verify(token: string, nowSeconds?: number): VerifiedIdentity;
}

export interface GatewayAssertionSettings {
  issuer: string;
  audience: string;
  publicKeyPem: string;
  maxLifetimeSeconds?: number;
}

const B64URL = /^[A-Za-z0-9_-]+$/;
const MAX_TOKEN_LENGTH = 8192;

function decodePart(part: string): unknown {
  if (!B64URL.test(part)) throw new Error('Invalid gateway assertion encoding');
  const buffer = Buffer.from(part, 'base64url');
  if (buffer.toString('base64url') !== part) throw new Error('Noncanonical gateway assertion encoding');
  try { return JSON.parse(buffer.toString('utf8')); }
  catch { throw new Error('Invalid gateway assertion JSON'); }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid gateway assertion object');
  return value as Record<string, unknown>;
}

/**
 * Verifies an Ed25519-signed compact JWT issued by a trusted gateway.
 * This verifier does not validate OAuth access tokens. Gateway identity must
 * still be resolved through the local issuer+subject target policy.
 *
 * NOTE: This only validates signature and temporal claims. It does NOT provide
 * replay protection or bind an assertion to a specific HTTP request. Until
 * those controls are implemented, do not use it as public HTTP authentication.
 */
export function createGatewayAssertionVerifier(settings: GatewayAssertionSettings): GatewayAssertionVerifier {
  if (!settings.issuer || !settings.audience || !settings.publicKeyPem) throw new Error('Gateway verifier requires issuer, audience, and public key');
  const maxLifetime = settings.maxLifetimeSeconds ?? 60;
  if (!Number.isSafeInteger(maxLifetime) || maxLifetime < 1 || maxLifetime > 300) throw new Error('Invalid gateway assertion maximum lifetime');
  const key: KeyObject = createPublicKey(settings.publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Gateway assertion key must be Ed25519');
  return {
    verify(token, nowSeconds = Math.floor(Date.now() / 1000)) {
      if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) throw new Error('Invalid gateway assertion length');
      const parts = token.split('.');
      if (parts.length !== 3 || !parts.every(part => B64URL.test(part))) throw new Error('Invalid gateway assertion format');
      const header = object(decodePart(parts[0]));
      if (header.alg !== 'EdDSA' || header.typ !== 'JWT' || Object.keys(header).some(k => !['alg', 'typ'].includes(k))) {
        throw new Error('Unsupported gateway assertion header');
      }
      const signature = Buffer.from(parts[2], 'base64url');
      if (signature.length !== 64 || signature.toString('base64url') !== parts[2] ||
          !verify(null, Buffer.from(parts[0] + '.' + parts[1]), key, signature)) {
        throw new Error('Invalid gateway assertion signature');
      }
      const claims = object(decodePart(parts[1]));
      if (Object.keys(claims).some(k => !['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti'].includes(k))) throw new Error('Unsupported gateway assertion claim');
      if (claims.iss !== settings.issuer || claims.aud !== settings.audience ||
          typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 512 ||
          typeof claims.jti !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(claims.jti)) {
        throw new Error('Invalid gateway assertion identity or audience');
      }
      const { iat, nbf, exp } = claims;
      if (![iat, nbf, exp].every(x => typeof x === 'number' && Number.isSafeInteger(x)) ||
          !Number.isSafeInteger(nowSeconds) || (iat as number) > nowSeconds + 5 ||
          (nbf as number) > nowSeconds + 5 || (exp as number) <= nowSeconds ||
          (exp as number) <= (iat as number) || (exp as number) - (iat as number) > maxLifetime ||
          (iat as number) < nowSeconds - maxLifetime - 5) {
        throw new Error('Expired or invalid gateway assertion time');
      }
      return { issuer: claims.iss as string, subject: claims.sub as string };
    },
  };
}
