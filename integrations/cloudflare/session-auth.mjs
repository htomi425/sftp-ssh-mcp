/**
 * Adapter for a real session verifier supplied by the deployment's IdP.
 * verifySession MUST validate signature/MAC, issuer, audience, expiry,
 * revocation and cookie binding server-side. Never trust raw cookie claims.
 */
export function createSessionAuthenticator({ verifySession, cookieName = '__Host-ssh_mcp_session' }) {
  if (typeof verifySession !== 'function') throw new Error('Trusted session verifier required');
  if (!/^__Host-[A-Za-z0-9_-]+$/.test(cookieName)) {
    throw new Error('Session cookie must use __Host- prefix');
  }
  return async function authenticateUser(request, env) {
    const raw = request.headers.get('Cookie') ?? '';
    if (raw.length > 8192) return null;
    const cookies = raw.split(';').map(part => part.trim()).filter(Boolean);
    const values = cookies.filter(part => part.startsWith(cookieName + '='));
    if (values.length !== 1) return null;
    const token = values[0].slice(cookieName.length + 1);
    if (!/^[A-Za-z0-9_-]{32,2048}$/.test(token)) return null;
    let identity;
    try { identity = await verifySession(token, env); } catch { return null; }
    if (!identity || typeof identity.id !== 'string' || !identity.id ||
        typeof identity.issuer !== 'string' || !identity.issuer ||
        identity.id.length > 512 || identity.issuer.length > 2048) return null;
    return { id: identity.id, issuer: identity.issuer };
  };
}
