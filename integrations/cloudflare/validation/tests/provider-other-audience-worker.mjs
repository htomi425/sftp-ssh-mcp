import { OAuthResourceServer, insufficientScope } from '@cloudflare/workers-oauth-provider';

// Deliberately distinct protected resource: tokens issued for /mcp must not
// authenticate this endpoint, even when issuer and requested scope match.
const server = new OAuthResourceServer({
  resourceMetadata: {
    resource: 'https://other-resource.example.invalid/mcp',
    authorization_servers: ['https://auth.example.invalid'],
  },
  requiredScopes: ['mcp:invoke'],
  validateToken: env => env.AUTH_SERVER.validateToken,
  handler: {
    fetch(request, env, ctx) {
      if (!ctx.auth.scope.includes('mcp:invoke')) {
        return insufficientScope(ctx.auth, ['mcp:invoke']);
      }
      return new Response('authorized');
    },
  },
});
export default { fetch(request, env, ctx) { return server.fetch(request, env, ctx); } };
