import type { HttpPrincipal } from './http-access.js';
import type { Target, TargetRegistry } from './ssh/targets.js';

/**
 * Resolve the target for a single authenticated HTTP MCP request.
 * Never infer a target from the whole registry when a principal is restricted.
 */
export function selectAuthorizedTarget(
  registry: TargetRegistry,
  principal: HttpPrincipal,
  requestedName?: string,
): { name: string; target: Target } {
  if (requestedName !== undefined && (typeof requestedName !== 'string' || !requestedName)) {
    throw new Error('Invalid SSH target name');
  }
  const allowed = Object.keys(registry).filter(name => principal.targets.has(name));
  const name = requestedName ??
    (allowed.includes('default') ? 'default' : allowed.length === 1 ? allowed[0] : undefined);
  if (!name || !Object.hasOwn(registry, name) || !principal.targets.has(name)) {
    throw new Error('SSH target unavailable or access denied');
  }
  return { name, target: registry[name] };
}
