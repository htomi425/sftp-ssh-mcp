/**
 * Cloudflare resource gateway building block (not a deployed OAuth server).
 * The caller MUST provide an OAuth access-token verifier that validates issuer,
 * audience, expiry, scope and token revocation as appropriate. Never use an
 * Access JWT or ID token as an OAuth access token by default.
 *
 * The upstream binding MUST be private and must route to the Node HTTP origin.
 * This module deliberately does not configure public routes or credentials.
 */
const encoder = new TextEncoder();
const B64URL = bytes => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};
const encode = value => B64URL(encoder.encode(JSON.stringify(value)));
const json = (status, message, headers = {}) => new Response(JSON.stringify({ error: message }), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
});

/**
 * @param {Request} request
 * @param {{ ORIGIN: { fetch(request: Request): Promise<Response> }, GATEWAY_PRIVATE_KEY: string, GATEWAY_ISSUER: string, GATEWAY_AUDIENCE: string }} env
 * @param {(bearer: string, resource: string) => Promise<{issuer:string,subject:string,scopes:string[]}>} verifyAccessToken
 * @param {{resource:string,requiredScope:string}} settings
 */
export async function handleResourceRequest(request, env, verifyAccessToken, settings) {
  const url = new URL(request.url);
  const challenge = `Bearer resource_metadata="${new URL('/.well-known/oauth-protected-resource/mcp', url.origin)}"`;
  if (url.pathname !== '/mcp' || !['POST', 'GET', 'DELETE'].includes(request.method) || url.search) {
    return json(404, 'not_found');
  }
  if (request.headers.has('Origin')) return json(403, 'origin_not_allowed');
  const auth = request.headers.get('Authorization');
  const match = auth && /^Bearer ([A-Za-z0-9._~-]{16,8192})$/.exec(auth);
  if (!match) return json(401, 'invalid_token', { 'WWW-Authenticate': challenge });
  let identity;
  try {
    identity = await verifyAccessToken(match[1], settings.resource);
    if (!identity || typeof identity.issuer !== 'string' || !identity.issuer ||
        typeof identity.subject !== 'string' || !identity.subject ||
        !Array.isArray(identity.scopes) || !identity.scopes.includes(settings.requiredScope)) {
      return json(403, 'insufficient_scope', { 'WWW-Authenticate': challenge + ', error="insufficient_scope"' });
    }
  } catch {
    return json(401, 'invalid_token', { 'WWW-Authenticate': challenge });
  }
  return forwardVerifiedIdentity(request, env, identity, settings);
}

/**
 * Forward only a verified OAuth identity. The caller MUST be the
 * OAuthResourceServer's handler after Service Binding token validation.
 */
export async function forwardVerifiedIdentity(request, env, identity, settings) {
  const url = new URL(request.url);
  if (url.pathname !== '/mcp' || url.search ||
      !['POST', 'GET', 'DELETE'].includes(request.method) ||
      request.headers.has('Origin')) return json(403, 'request_not_allowed');
  if (!identity || typeof identity.issuer !== 'string' || !identity.issuer ||
      typeof identity.subject !== 'string' || !identity.subject ||
      !Array.isArray(identity.scopes) || !identity.scopes.includes(settings.requiredScope)) {
    return json(403, 'insufficient_scope');
  }
  // Node origin accepts at most 16 MiB; bound the request at the gateway too.
  if (Number(request.headers.get('Content-Length')) > 16 * 1024 * 1024) return json(413, 'body_too_large');
  const raw = new Uint8Array(await request.arrayBuffer());
  if (raw.byteLength > 16 * 1024 * 1024) return json(413, 'body_too_large');
  const now = Math.floor(Date.now() / 1000);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));
  const claims = {
    iss: env.GATEWAY_ISSUER, sub: JSON.stringify([identity.issuer, identity.subject]),
    aud: env.GATEWAY_AUDIENCE, iat: now, nbf: now, exp: now + 30,
    jti: B64URL(crypto.getRandomValues(new Uint8Array(24))),
    htm: request.method, htu: '/mcp', body_sha256: B64URL(digest),
  };
  // The origin identity policy must map gateway issuer + serialized upstream identity.
  const pem = env.GATEWAY_PRIVATE_KEY.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, '');
  const der = Uint8Array.from(atob(pem), char => char.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
  const input = encode({ alg: 'EdDSA', typ: 'JWT' }) + '.' + encode(claims);
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', key, encoder.encode(input)));
  const headers = new Headers(request.headers);
  // Never forward caller-provided identity, assertion, or proxy credentials.
  for (const name of [...headers.keys()]) {
    if (/^(x-|cf-|authorization$|cookie$|host$|content-length$|transfer-encoding$|connection$|proxy-)/i.test(name)) headers.delete(name);
  }
  headers.set('Authorization', 'Bearer ' + input + '.' + B64URL(signature));
  headers.set('Cache-Control', 'no-store');
  return env.ORIGIN.fetch(new Request('https://origin.internal/mcp', {
    method: request.method, headers, body: request.method === 'POST' ? raw : undefined,
    redirect: 'manual',
  }));
}
