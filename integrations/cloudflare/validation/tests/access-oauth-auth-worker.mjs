import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
import { OAuthAuthorizationServer, OAuthError } from '@cloudflare/workers-oauth-provider';
import { createAuthorizationEntrypoint } from '../../authorization-worker.mjs';
import { createAccessAuthorizationWorker } from '../../consent-authorization-worker.mjs';
import { createOAuthSubjectState } from '../../access-grants.mjs';

export const OAuthSubjectState = createOAuthSubjectState(DurableObject);
const worker = createAccessAuthorizationWorker({
  OAuthAuthorizationServer,
  OAuthError,
  providerOptions: {
    issuer: 'https://auth.example.invalid',
    resources: ['https://resource.example.invalid/mcp'],
    scopesSupported: ['mcp:invoke'],
    clientRegistrationEndpoint: '/oauth/register',
  },
  access: {
    issuer: 'https://test-team.cloudflareaccess.com',
    audience: 'a'.repeat(64),
  },
});

export const AuthServer = createAuthorizationEntrypoint(WorkerEntrypoint, worker);

export class TestAdmin extends WorkerEntrypoint {
  setStopped(subject, stopped) {
    return worker.setSubjectStopped(this.env, subject, stopped);
  }
}

export default {
  fetch(request, env, ctx) {
    // Reconstruct the browser Origin screened by Miniflare's local proxy.
    if (request.method === 'POST' && new URL(request.url).pathname === '/authorize') {
      const headers = new Headers(request.headers);
      headers.set('Origin', new URL(request.url).origin);
      request = new Request(request, { headers });
    }
    return worker.fetch(request, env, ctx);
  },
};
