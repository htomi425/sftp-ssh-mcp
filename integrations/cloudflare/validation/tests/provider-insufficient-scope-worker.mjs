import { OAuthResourceServer, insufficientScope } from '@cloudflare/workers-oauth-provider';

const requiredScope = 'mcp:admin';
const server = new OAuthResourceServer({
  resourceMetadata: {
    resource: 'https://resource.example.invalid/mcp',
    authorization_servers: ['https://auth.example.invalid'],
  },
  requiredScopes: [requiredScope],
  validateToken: env => env.AUTH_SERVER.validateToken,
  handler: {
    fetch(request, env, ctx) {
      if (!ctx.auth.scope.includes(requiredScope)) {
        return insufficientScope(ctx.auth, [requiredScope]);
      }
      return new Response('authorized');
    },
  },
});
export default { fetch(request, env, ctx) { return server.fetch(request, env, ctx); } };
