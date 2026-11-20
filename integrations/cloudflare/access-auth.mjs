const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const keyIdPattern = /^[a-f0-9]{64}$/i;

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid JWT encoding');
  const raw = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  if (btoa(raw).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') !== value) {
    throw new Error('Invalid JWT encoding');
  }
  return Uint8Array.from(raw, char => char.charCodeAt(0));
}

export function createAccessAuthenticator({ issuer, audience, fetchKeys = fetch }) {
  if (typeof issuer !== 'string' || !/^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(issuer) ||
      typeof audience !== 'string' || !/^[a-f0-9]{64}$/.test(audience)) {
    throw new Error('Cloudflare Access team issuer and application audience required');
  }
  const jwksUrl = issuer + '/cdn-cgi/access/certs';
  let keys = new Map();
  let expires = 0;
  let retryAfter = 0;

  async function signingKey(kid) {
    const now = Date.now();
    if (now < expires && keys.has(kid)) return keys.get(kid);
    if (now < retryAfter) return null;
    // Keep fetch I/O scoped to this request. Workers cannot share in-flight I/O.
    const response = await fetchKeys(jwksUrl, {
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error('Access signing keys unavailable');
    const jwks = await response.json();
    if (!Array.isArray(jwks?.keys) || jwks.keys.length > 32) throw new Error('Invalid Access JWKS');
    const next = new Map();
    for (const key of jwks.keys) {
      if (key?.kty !== 'RSA' || key.alg !== 'RS256' || key.use !== 'sig' ||
          typeof key.kid !== 'string' || !keyIdPattern.test(key.kid)) continue;
      if (next.has(key.kid)) throw new Error('Duplicate Access signing key ID');
      const publicKey = await crypto.subtle.importKey('jwk', key, algorithm, false, ['verify']);
      if (publicKey.algorithm.modulusLength < 2048) throw new Error('Invalid Access signing key size');
      next.set(key.kid, publicKey);
    }
    keys = next;
    expires = Date.now() + 300000;
    if (!keys.has(kid)) retryAfter = Date.now() + 5000;
    return keys.get(kid);
  }

  return async function authenticateAccessUser(request) {
    const jwt = request.headers.get('Cf-Access-Jwt-Assertion');
    if (!jwt || jwt.length > 8192) return null;
    try {
      const segments = jwt.split('.');
      if (segments.length !== 3) return null;
      const [headerSegment, payloadSegment, signature] = segments;
      const header = JSON.parse(decoder.decode(decodeBase64Url(headerSegment)));
      if (header?.alg !== 'RS256' || typeof header.kid !== 'string' ||
          !keyIdPattern.test(header.kid) || header.crit !== undefined) return null;
      const claims = JSON.parse(decoder.decode(decodeBase64Url(payloadSegment)));
      const now = Math.floor(Date.now() / 1000);
      if (claims?.iss !== issuer || claims.type !== 'app' ||
          !Array.isArray(claims.aud) || !claims.aud.includes(audience) ||
          typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 512 ||
          typeof claims.email !== 'string' || !claims.email || Object.hasOwn(claims, 'common_name') ||
          !Number.isSafeInteger(claims.exp) || claims.exp <= now ||
          !Number.isSafeInteger(claims.iat) || claims.iat > now ||
          (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > now))) return null;
      const signatureBytes = decodeBase64Url(signature);
      if (signatureBytes.byteLength < 256) return null;
      const key = await signingKey(header.kid);
      if (!key || !await crypto.subtle.verify(algorithm, key, signatureBytes,
        encoder.encode(headerSegment + '.' + payloadSegment))) return null;
      if (claims.exp <= Math.floor(Date.now() / 1000)) return null;
      return { id: claims.sub, issuer, expiresAt: claims.exp };
    } catch {
      return null;
    }
  };
}
