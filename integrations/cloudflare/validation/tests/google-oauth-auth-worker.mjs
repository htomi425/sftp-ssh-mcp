import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
import { OAuthAuthorizationServer, OAuthError } from '@cloudflare/workers-oauth-provider';
import { createAuthorizationEntrypoint } from '../../authorization-worker.mjs';
import { createOAuthSubjectState } from '../../access-grants.mjs';
import { createGoogleAuthorizationFlow, createGoogleAuthorizationWorker } from '../../google-authorization.mjs';

export const OAuthSubjectState = createOAuthSubjectState(DurableObject);
export const GoogleAuthorizationFlow = createGoogleAuthorizationFlow(DurableObject);
const worker = createGoogleAuthorizationWorker({
  OAuthAuthorizationServer,
  OAuthError,
  providerOptions: {
    issuer: 'https://auth.example.invalid',
    resources: ['https://resource.example.invalid/mcp'],
    scopesSupported: ['mcp:invoke'],
    clientRegistrationEndpoint: '/oauth/register',
  },
});

export const AuthServer = createAuthorizationEntrypoint(WorkerEntrypoint, worker);

export default {
  fetch(request, env, ctx) {
    // Miniflare's local proxy screens Origin.
    if (request.method === 'POST' && new URL(request.url).pathname === '/authorize') {
      const headers = new Headers(request.headers);
      headers.set('Origin', new URL(request.url).origin);
      request = new Request(request, { headers });
    }
    return worker.fetch(request, env, ctx);
  },
};
