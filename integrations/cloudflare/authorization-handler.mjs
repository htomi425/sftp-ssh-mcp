/**
 * OAuthAuthorizationServer v1 /authorize handler.
 *
 * authenticateUser MUST validate a real login session (not request parameters).
 * renderConsent MUST render an explicit approval/denial UI with a server-issued
 * consent handle. Never infer approval from a GET or user-supplied identity.
 */
export function createAuthorizationHandler({ getOAuthApi, authenticateUser, renderConsent }) {
  if (![getOAuthApi, authenticateUser, renderConsent].every(fn => typeof fn === 'function')) {
    throw new Error('OAuth API, trusted user authentication and consent renderer required');
  }
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      if (url.pathname !== '/authorize' || !['GET', 'POST'].includes(request.method)) {
        return new Response('Not found', { status: 404 });
      }
      if (request.headers.has('Origin') && new URL(request.headers.get('Origin')).origin !== url.origin) {
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
        return renderConsent({ request, user, details, consent });
      }
      // No grant without a valid CSRF-protected consent handle from provider.
      const form = await request.formData();
      const handle = form.get('handle');
      if (typeof handle !== 'string' || !handle || handle.length > 2048) {
        return new Response('Invalid consent handle', { status: 400 });
      }
      const decision = form.get('decision');
      if (decision === 'deny') {
        const denied = await oauth.denyConsent(request, handle);
        return new Response(null, { status: 302, headers: denied.headers });
      }
      if (decision !== 'approve') return new Response('Invalid consent decision', { status: 400 });
      // Scope is selected by the provider's stored request, not POST form data.
      const approved = await oauth.approveConsent(request, handle, {
        scope: ['mcp:invoke'],
      });
      if (!approved?.request || !Array.isArray(approved.request.scope) ||
          !approved.request.scope.includes('mcp:invoke')) {
        return new Response('Requested scope not permitted', { status: 403 });
      }
      const { redirectTo } = await oauth.completeAuthorization({
        request: approved.request,
        userId: user.id,
        metadata: {},
        scope: ['mcp:invoke'],
        props: { userId: user.id, issuer: user.issuer },
      });
      return Response.redirect(redirectTo, 302);
    },
  };
}
