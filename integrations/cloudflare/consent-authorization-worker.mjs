import { createAuthorizationWorker } from './authorization-worker.mjs';
import { createSessionAuthenticator } from './session-auth.mjs';
import { renderOAuthConsent } from './consent-ui.mjs';
import { createConsentIdentityBinding } from './consent-identity-binding.mjs';

/**
 * Composes the production-facing authorization flow without embedding an IdP.
 * verifySession must independently validate the session against a trusted IdP
 * or a server-controlled session store, including expiry and revocation.
 */
export function createConsentAuthorizationWorker({ authorizationServer, verifySession, cookieName, consentSigningSecret }) {
  return createAuthorizationWorker({
    authorizationServer,
    authenticateUser: createSessionAuthenticator({ verifySession, cookieName }),
    renderConsent: renderOAuthConsent,
    bindConsent: createConsentIdentityBinding(consentSigningSecret),
  });
}

/**
 * Runtime-secret variant for Cloudflare Workers. The signing key is read
 * exclusively from the trusted env secret binding, never request headers.
 * OAuth discovery/token endpoints remain available even if the consent
 * secret is temporarily missing; /authorize fails closed with 503.
 */
export function createEnvConsentAuthorizationWorker({
  authorizationServer, verifySession, cookieName,
  secretBinding = 'OAUTH_CONSENT_SIGNING_SECRET',
}) {
  if (!/^[A-Z][A-Z0-9_]{0,127}$/.test(secretBinding)) {
    throw new Error('Invalid OAuth consent signing secret binding name');
  }
  // Validate non-secret dependencies at construction.
  const authenticated = createSessionAuthenticator({ verifySession, cookieName });
  if (!authorizationServer ||
      typeof authorizationServer.getOAuthApi !== 'function' ||
      typeof authorizationServer.fetch !== 'function' ||
      typeof authorizationServer.validateToken !== 'function') {
    throw new Error('OAuthAuthorizationServer v1 instance required');
  }
  return {
    async fetch(request, env, ctx) {
      if (new URL(request.url).pathname !== '/authorize') {
        return authorizationServer.fetch(request, env, ctx);
      }
      const secret = env?.[secretBinding];
      if (typeof secret !== 'string' || secret.length < 32) {
        return new Response('Authorization service unavailable', { status: 503,
          headers: { 'Cache-Control': 'no-store' } });
      }
      const worker = createAuthorizationWorker({
        authorizationServer, authenticateUser: authenticated,
        renderConsent: renderOAuthConsent,
        bindConsent: createConsentIdentityBinding(secret),
      });
      return worker.fetch(request, env, ctx);
    },
    validateToken(resource, token, env) {
      return authorizationServer.validateToken(resource, token, env);
    },
  };
}
