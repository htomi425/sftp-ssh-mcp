/**
 * Resource handler for OAuthResourceServer v1, AFTER its Service Binding
 * token validation. Do not call this handler directly with caller-supplied ctx.
 */
export function createVerifiedResourceHandler({ forward, insufficientScope, requiredScope = 'mcp:invoke' }) {
  if (typeof forward !== 'function' || typeof insufficientScope !== 'function') {
    throw new Error('Verified forwarder and insufficient-scope responder required');
  }
  return {
    async fetch(request, env, ctx) {
      // OAuthResourceServer's requiredScopes advertises scopes but does not
      // itself enforce them; check the validated context before forwarding.
      if (!ctx || !ctx.auth || !Array.isArray(ctx.auth.scope) ||
          !ctx.auth.scope.includes(requiredScope)) {
        if (!ctx?.auth) return new Response('Unauthorized', { status: 401 });
        return insufficientScope(ctx.auth, [requiredScope]);
      }
      const props = ctx.props;
      if (!props || typeof props !== 'object' ||
          typeof props.userId !== 'string' || !props.userId ||
          typeof props.issuer !== 'string' || !props.issuer) {
        return new Response('Unauthorized', { status: 401 });
      }
      return forward(request, env, {
        issuer: props.issuer,
        subject: props.userId,
        scopes: ctx.auth.scope,
      });
    },
  };
}
