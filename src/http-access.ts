import { createHash, timingSafeEqual } from 'node:crypto';

export interface HttpPrincipal {
  id: string;
  targets: ReadonlySet<string>;
}

export interface HttpAccessPolicy {
  authenticate(authorization: string | undefined): HttpPrincipal;
  authorize(principal: HttpPrincipal, targetName: string): void;
}

interface Credential {
  id: string;
  tokenHash: Buffer;
  targets: ReadonlySet<string>;
}

const ID = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;
const TOKEN = /^[A-Za-z0-9._~-]{32,512}$/;

function digest(token: string): Buffer {
  return createHash('sha256').update(token).digest();
}

/**
 * Explicit, static credentials for the reverse-proxy-facing HTTP transport.
 * OAuth token validation will be integrated separately. Never accept arbitrary
 * bearer tokens, and never fall back to the stdio execution permissions.
 */
export function parseHttpAccessPolicy(raw: string | undefined, knownTargets: ReadonlySet<string>): HttpAccessPolicy {
  if (!raw) throw new Error('SSH_MCP_HTTP_CREDENTIALS is required for HTTP authentication');
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error('SSH_MCP_HTTP_CREDENTIALS must be valid JSON'); }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 32) {
    throw new Error('SSH_MCP_HTTP_CREDENTIALS must contain 1 to 32 credentials');
  }
  const credentials: Credential[] = [];
  const ids = new Set<string>();
  const hashes = new Set<string>();
  for (const entry of parsed) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('HTTP credential must be an object');
    const obj = entry as Record<string, unknown>;
    if (Object.keys(obj).some(key => !['id', 'token', 'targets'].includes(key))) throw new Error('Unknown HTTP credential field');
    if (typeof obj.id !== 'string' || !ID.test(obj.id) || ids.has(obj.id)) throw new Error('Invalid or duplicate HTTP credential id');
    if (typeof obj.token !== 'string' || !TOKEN.test(obj.token)) throw new Error('HTTP bearer token must be 32 to 512 URL-safe characters');
    if (!Array.isArray(obj.targets) || !obj.targets.length || obj.targets.length > 32 || obj.targets.some(t => typeof t !== 'string' || !knownTargets.has(t))) {
      throw new Error('HTTP credential references an unknown or empty target list');
    }
    if (new Set(obj.targets).size !== obj.targets.length) throw new Error('Duplicate HTTP credential target');
    const tokenHash = digest(obj.token);
    const hash = tokenHash.toString('hex');
    if (hashes.has(hash)) throw new Error('Duplicate HTTP bearer token');
    ids.add(obj.id);
    hashes.add(hash);
    credentials.push({ id: obj.id, tokenHash, targets: new Set(obj.targets) });
  }
  return {
    authenticate(authorization) {
      const match = typeof authorization === 'string' ? /^Bearer ([A-Za-z0-9._~-]{32,512})$/.exec(authorization) : null;
      if (!match) throw new Error('HTTP authentication required');
      const candidate = digest(match[1]);
      let selected: Credential | undefined;
      for (const credential of credentials) {
        if (timingSafeEqual(candidate, credential.tokenHash)) selected = credential;
      }
      if (!selected) throw new Error('HTTP authentication failed');
      return { id: selected.id, targets: selected.targets };
    },
    authorize(principal, targetName) {
      if (!principal.targets.has(targetName)) throw new Error('SSH target access denied');
    },
  };
}
