import type { HttpPrincipal } from './http-access.js';

export interface VerifiedIdentity {
  issuer: string;
  subject: string;
}

export interface IdentityTargetPolicy {
  resolve(identity: VerifiedIdentity): HttpPrincipal;
}

const SUBJECT_MAX_LENGTH = 512;
const ISSUER_MAX_LENGTH = 2048;

function identityKey(identity: VerifiedIdentity): string {
  if (typeof identity.issuer !== 'string' || !identity.issuer || identity.issuer.length > ISSUER_MAX_LENGTH ||
      typeof identity.subject !== 'string' || !identity.subject || identity.subject.length > SUBJECT_MAX_LENGTH) {
    throw new Error('Invalid verified identity');
  }
  // Length-delimited components prevent delimiter-based identity collisions.
  return JSON.stringify([identity.issuer, identity.subject]);
}

/**
 * Maps a previously verified issuer+subject identity to a local SSH target
 * allowlist. This module does NOT authenticate requests or verify OAuth tokens.
 */
export function parseIdentityTargetPolicy(raw: string | undefined, knownTargets: ReadonlySet<string>): IdentityTargetPolicy {
  if (!raw) throw new Error('SSH_MCP_IDENTITY_TARGETS is required for identity authorization');
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error('SSH_MCP_IDENTITY_TARGETS must be valid JSON'); }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 256) {
    throw new Error('SSH_MCP_IDENTITY_TARGETS must contain 1 to 256 mappings');
  }
  const mappings = new Map<string, HttpPrincipal>();
  for (const entry of parsed) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('Identity mapping must be an object');
    const item = entry as Record<string, unknown>;
    if (Object.keys(item).some(key => !['issuer', 'subject', 'targets'].includes(key))) throw new Error('Unknown identity mapping field');
    const key = identityKey({ issuer: item.issuer as string, subject: item.subject as string });
    if (mappings.has(key)) throw new Error('Duplicate identity mapping');
    if (!Array.isArray(item.targets) || !item.targets.length || item.targets.length > 32 ||
        item.targets.some(target => typeof target !== 'string' || !knownTargets.has(target))) {
      throw new Error('Identity mapping references unknown or empty targets');
    }
    if (new Set(item.targets).size !== item.targets.length) throw new Error('Duplicate identity target');
    const identity = JSON.parse(key) as [string, string];
    mappings.set(key, { id: key, targets: new Set(item.targets as string[]) });
  }
  return {
    resolve(identity) {
      const principal = mappings.get(identityKey(identity));
      if (!principal) throw new Error('Identity is not authorized for SSH access');
      return principal;
    },
  };
}
