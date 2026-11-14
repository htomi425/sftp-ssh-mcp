import { createConsentAuthorizationWorker } from '../../consent-authorization-worker.mjs';
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

// Local-test-only trusted session verifier; NEVER deploy this entrypoint.
// Real deployments must supply an independent IdP-backed verifier.
const consentWorker = createConsentAuthorizationWorker({
  authorizationServer,
  verifySession: async (token, env) =>
    env.TEST_ENABLE_AUTHORIZATION === 'enabled-for-local-tests-only' &&
    token === env.TEST_SESSION_TOKEN
      ? { id: 'test-user', issuer: 'https://test-idp.example.invalid' } : null,
});
async function handleAuthorization(request, env) {
  if (env.TEST_ENABLE_AUTHORIZATION !== 'enabled-for-local-tests-only') {
    return new Response('Disabled', { status: 403 });
  }
  return consentWorker.fetch(request, env);
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
