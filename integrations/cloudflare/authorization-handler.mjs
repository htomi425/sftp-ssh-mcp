/**
 * OAuthAuthorizationServer v1 /authorize handler.
 *
 * authenticateUser MUST validate a real login session (not request parameters).
 * renderConsent MUST render an explicit approval/denial UI with a server-issued
 * consent handle. Never infer approval from a GET or user-supplied identity.
 */
export function createAuthorizationHandler({ getOAuthApi, authenticateUser, renderConsent, bindConsent }) {
  if (![getOAuthApi, authenticateUser, renderConsent].every(fn => typeof fn === 'function')) {
    throw new Error('OAuth API, trusted user authentication and consent renderer required');
  }
  if (!bindConsent || typeof bindConsent.issue !== 'function' ||
      typeof bindConsent.verify !== 'function') {
    throw new Error('OAuth consent identity binding is required');
  }
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      if (url.pathname !== '/authorize' || !['GET', 'POST'].includes(request.method)) {
        return new Response('Not found', { status: 404 });
      }
      // Consent is a state-changing browser action. Require a same-origin
      // Origin header rather than relying on cookies or a caller-provided handle.
      // Never let malformed Origin values escape as an unhandled exception.
      if (request.method === 'POST') {
        const origin = request.headers.get('Origin');
        if (!origin || origin === 'null' || origin !== url.origin) {
          return new Response('Forbidden', { status: 403 });
        }
        const contentType = request.headers.get('Content-Type') || '';
        if (contentType.toLowerCase().split(";")[0].trim() !== "application/x-www-form-urlencoded") {
          return new Response('Unsupported media type', { status: 415 });
        }
      } else if (request.headers.has('Origin') && request.headers.get('Origin') !== url.origin) {
        return new Response('Forbidden', { status: 403 });
      }
      // Must be backed by an authenticated session; no anonymous grants.
      const user = await authenticateUser(request, env);
      if (!user || typeof user.id !== 'string' || !user.id ||
          typeof user.issuer !== 'string' || !user.issuer) {
        return new Response('Login required', { status: 401 });
      }
      const oauth = getOAuthApi(env);
      if (request.method === 'GET') {
        const authRequest = await oauth.parseAuthRequest(request);
        const details = await oauth.describeConsent(authRequest);
        const consent = await oauth.beginConsent(authRequest);
        const bound = await bindConsent.issue(consent.handle, user, env);
        return renderConsent({ request, user, details, consent: { ...consent, handle: bound } });
      }
      // Bound the consent body before invoking formData(): chunked requests
      // without Content-Length must not consume unbounded Worker memory.
      // Read a clone so the original provider request remains available.
      const maxConsentBodyBytes = 8192;
      const declaredLength = request.headers.get('Content-Length');
      if (declaredLength !== null &&
          (!/^[0-9]+$/.test(declaredLength) || Number(declaredLength) > maxConsentBodyBytes)) {
        return new Response('Consent form too large', { status: 413 });
      }
      let form;
      try {
        const reader = request.clone().body?.getReader();
        if (!reader) return new Response('Invalid consent form', { status: 400 });
        let size = 0;
        let oversized = false;
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > maxConsentBodyBytes) {
              oversized = true;
              await reader.cancel().catch(() => {});
              break;
            }
          }
        } finally {
          reader.releaseLock();
        }
        if (oversized) return new Response('Consent form too large', { status: 413 });
        // No grant without a valid CSRF-protected consent handle from provider.
        form = await request.formData();
      } catch {
        return new Response('Invalid consent form', { status: 400 });
      }
      if (form.getAll('handle').length !== 1 || form.getAll('decision').length !== 1 ||
          [...form.keys()].some(key => key !== 'handle' && key !== 'decision')) {
        return new Response('Invalid consent form', { status: 400 });
      }
      const handle = form.get('handle');
      if (typeof handle !== 'string' || !handle || handle.length > 2048) {
        return new Response('Invalid consent handle', { status: 400 });
      }
      const providerHandle = await bindConsent.verify(handle, user, env);
      if (!providerHandle) return new Response('Consent identity mismatch', { status: 403 });
      const decision = form.get('decision');
      if (decision === 'deny') {
        const denied = await oauth.denyConsent(request, providerHandle);
        return new Response(null, { status: 302, headers: denied.headers });
      }
      if (decision !== 'approve') return new Response('Invalid consent decision', { status: 400 });
      // Scope is selected by the provider's stored request, not POST form data.
      const approved = await oauth.approveConsent(request, providerHandle, {
        scope: ['mcp:invoke'],
      });
      if (!approved?.request || !Array.isArray(approved.request.scope) ||
          !approved.request.scope.includes('mcp:invoke') ||
          approved.request.scope.some(scope => scope !== 'mcp:invoke')) {
        return new Response('Requested scope not permitted', { status: 403 });
      }
      const { redirectTo } = await oauth.completeAuthorization({
        request: approved.request,
        userId: user.id,
        metadata: {},
        scope: ['mcp:invoke'],
        props: { userId: user.id, issuer: user.issuer },
      });
      // Preserve the OAuth provider's response headers (including consent
      // cookie updates) when redirecting to the validated OAuth client.
      const headers = new Headers(approved.headers);
      headers.set('Location', redirectTo);
      return new Response(null, { status: 302, headers });
    },
  };
}
