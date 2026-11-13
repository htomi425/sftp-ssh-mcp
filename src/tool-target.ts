import type { HttpPrincipal } from './http-access.js';
import { selectAuthorizedTarget } from './http-targets.js';
import { selectTarget, type Target, type TargetRegistry } from './ssh/targets.js';

export interface ToolExecutionContext {
  principal?: HttpPrincipal;
}

/**
 * A single target resolution boundary for every MCP tool.
 * Stdio calls have no HTTP principal and retain legacy target selection.
 * HTTP calls MUST supply the authenticated principal for each invocation.
 */
export function resolveToolTarget(
  registry: TargetRegistry,
  requestedName: string | undefined,
  context: ToolExecutionContext,
  transport: 'stdio' | 'http',
): Target {
  if (transport === 'http') {
    if (!context.principal) throw new Error('HTTP MCP tool execution requires an authenticated principal');
    return selectAuthorizedTarget(registry, context.principal, requestedName).target;
  }
  if (context.principal) throw new Error('HTTP principal cannot be used with stdio execution');
  return selectTarget(registry, requestedName);
}
