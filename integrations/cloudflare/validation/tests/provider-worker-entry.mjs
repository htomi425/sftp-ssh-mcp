import { OAuthResourceServer, insufficientScope } from '@cloudflare/workers-oauth-provider';

const server = new OAuthResourceServer({
  resourceMetadata: {
    resource: 'https://resource.example.invalid/mcp',
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

export default {
  fetch(request, env, ctx) {
    return server.fetch(request, env, ctx);
  },
};
