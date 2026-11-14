import { createAuthorizationWorker } from './authorization-worker.mjs';
import { createSessionAuthenticator } from './session-auth.mjs';
import { renderOAuthConsent } from './consent-ui.mjs';

/**
 * Composes the production-facing authorization flow without embedding an IdP.
 * verifySession must independently validate the session against a trusted IdP
 * or a server-controlled session store, including expiry and revocation.
 */
export function createConsentAuthorizationWorker({ authorizationServer, verifySession, cookieName }) {
  return createAuthorizationWorker({
    authorizationServer,
    authenticateUser: createSessionAuthenticator({ verifySession, cookieName }),
    renderConsent: renderOAuthConsent,
  });
}
