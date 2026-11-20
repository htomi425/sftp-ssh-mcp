import { createAccessAuthenticator } from './access-auth.mjs';
import { createAccessGrantPolicy, setAccessSubjectStopped } from './access-grants.mjs';
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
  return createEnvConsentWorker({
    authorizationServer, secretBinding,
    authenticateUser: createSessionAuthenticator({ verifySession, cookieName }),
  });
}

export function createAccessAuthorizationWorker({
  OAuthAuthorizationServer, OAuthError, providerOptions,
  access, secretBinding = 'OAUTH_CONSENT_SIGNING_SECRET',
}) {
  return createIdentityAuthorizationWorker({
    OAuthAuthorizationServer, OAuthError, providerOptions, secretBinding,
    issuer: access.issuer, authenticateUser: createAccessAuthenticator(access),
  });
}

export function createIdentityAuthorizationWorker({
  OAuthAuthorizationServer, OAuthError, providerOptions, issuer, authenticateUser,
  secretBinding = 'OAUTH_CONSENT_SIGNING_SECRET', browserAuthorization,
}) {
  const policy = createAccessGrantPolicy({
    authenticateAccessUser: authenticateUser, OAuthError,
  });
  const provider = new OAuthAuthorizationServer({
    ...providerOptions,
    refreshTokenIdleTTL: undefined,
    tokenExchangeCallback: policy.tokenExchangeCallback,
  });
  const worker = createEnvConsentWorker({
    authorizationServer: {
      fetch: (request, env, ctx) => provider.fetch(request, env, ctx),
      getOAuthApi: env => provider.getOAuthApi(env),
      validateToken: (resource, token, env) => policy.validateToken(provider, resource, token, env),
    },
    authenticateUser: policy.authenticateUser,
    prepareGrant: policy.prepareGrant,
    secretBinding,
  });
  return {
    ...worker,
    fetch(request, env, ctx) {
      if (!browserAuthorization) return worker.fetch(request, env, ctx);
      return browserAuthorization.fetch(request, env, ctx, worker,
        (incoming, bindings) => provider.getOAuthApi(bindings).parseAuthRequest(incoming));
    },
    setSubjectStopped(env, subject, stopped) {
      if (typeof subject !== 'string' || !subject || subject.length > 512) {
        throw new TypeError('OAuth subject required');
      }
      return setAccessSubjectStopped({
        env, oauth: provider.getOAuthApi(env), issuer, subject, stopped,
      });
    },
  };
}

function createEnvConsentWorker({ authorizationServer, authenticateUser, prepareGrant, secretBinding }) {
  if (!/^[A-Z][A-Z0-9_]{0,127}$/.test(secretBinding)) {
    throw new Error('Invalid OAuth consent signing secret binding name');
  }
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
      // Require a canonical base64url representation of a 32-byte key.
      // This validates the encoding and key size, not the quality of randomness.
      let validSecret = typeof secret === 'string' && /^[A-Za-z0-9_-]{43}$/.test(secret);
      let keyBytes;
      if (validSecret) {
        try {
          const decoded = atob(secret.replace(/-/g, '+').replace(/_/g, '/') + '=');
          keyBytes = Uint8Array.from(decoded, char => char.charCodeAt(0));
          validSecret = decoded.length === 32 &&
            btoa(decoded).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') === secret;
        } catch { validSecret = false; }
      }
      if (!validSecret) {
        return new Response('Authorization service unavailable', { status: 503,
          headers: { 'Cache-Control': 'no-store' } });
      }
      const worker = createAuthorizationWorker({
        authorizationServer, authenticateUser, prepareGrant,
        renderConsent: renderOAuthConsent,
        bindConsent: createConsentIdentityBinding(keyBytes),
      });
      return worker.fetch(request, env, ctx);
    },
    validateToken(resource, token, env) {
      return authorizationServer.validateToken(resource, token, env);
    },
  };
}
