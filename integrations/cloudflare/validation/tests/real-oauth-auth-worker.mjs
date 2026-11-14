import { OAuthAuthorizationServer } from '@cloudflare/workers-oauth-provider';
import { WorkerEntrypoint } from 'cloudflare:workers';

const authorizationServer = new OAuthAuthorizationServer({
  issuer: 'https://auth.example.invalid',
  resources: [
    'https://resource.example.invalid/mcp',
    'https://other-resource.example.invalid/mcp',
  ],
  scopesSupported: ['mcp:invoke'],
  clientIdMetadataDocumentEnabled: false,
  clientRegistrationEndpoint: '/oauth/register',
});

async function handleAuthorization(request, env) {
  if (env.TEST_ENABLE_AUTHORIZATION !== 'enabled-for-local-tests-only') {
    return new Response('Disabled', { status: 403 });
  }
  const oauth = authorizationServer.getOAuthApi(env);
  const parsed = await oauth.parseAuthRequest(request);
  // Test-only synthetic identity. Never deploy this entrypoint as a login handler.
  const result = await oauth.completeAuthorization({
    request: parsed, userId: 'test-user', metadata: {},
    scope: parsed.scope.filter(value => value === 'mcp:invoke'),
    props: { userId: 'test-user', issuer: 'https://test-idp.example.invalid' },
  });
  return Response.redirect(result.redirectTo, 302);
}

export class AuthServer extends WorkerEntrypoint {
  fetch(request) {
    if (new URL(request.url).pathname === '/authorize') {
      return handleAuthorization(request, this.env);
    }
    return authorizationServer.fetch(request, this.env, this.ctx);
  }
  validateToken(resource, token) {
    return authorizationServer.validateToken(resource, token, this.env);
  }
}

export default {
  fetch(request, env, ctx) {
    if (new URL(request.url).pathname === '/authorize') return handleAuthorization(request, env);
    return authorizationServer.fetch(request, env, ctx);
  },
};
