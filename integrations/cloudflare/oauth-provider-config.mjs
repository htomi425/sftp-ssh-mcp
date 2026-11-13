/**
 * Optional OAuth Provider composition for Cloudflare Workers.
 *
 * Requires @cloudflare/workers-oauth-provider in the separate Worker package.
 * No login/consent implementation is bundled: callers MUST supply an
 * authenticated, consent-aware authorization handler and a protected API
 * handler. Never approve arbitrary /authorize requests automatically.
 */
export function createOAuthProviderConfiguration({
  authorizationHandler,
  resourceHandler,
  resourceUrl,
  authorizationServerUrl,
}) {
  if (!authorizationHandler || typeof authorizationHandler.fetch !== 'function') {
    throw new Error('Authenticated OAuth authorization/consent handler required');
  }
  if (!resourceHandler || typeof resourceHandler.fetch !== 'function') {
    throw new Error('Protected OAuth resource handler required');
  }
  for (const [name, value] of [['resourceUrl', resourceUrl], ['authorizationServerUrl', authorizationServerUrl]]) {
    if (typeof value !== 'string') throw new Error(name + ' must be an HTTPS URL');
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
      throw new Error(name + ' must be an HTTPS URL without credentials, query, or fragment');
    }
  }
  const resource = new URL(resourceUrl);
  if (resource.pathname !== '/mcp') throw new Error('OAuth resource URL must end in /mcp');
  const issuer = new URL(authorizationServerUrl);
  if (issuer.pathname !== '/') throw new Error('OAuth issuer must be the origin URL');
  return {
    apiRoute: '/mcp',
    apiHandler: resourceHandler,
    defaultHandler: authorizationHandler,
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    scopesSupported: ['mcp:invoke'],
    resourceMetadata: {
      resource: resource.href,
      authorization_servers: [issuer.origin],
      scopes_supported: ['mcp:invoke'],
      bearer_methods_supported: ['header'],
      resource_name: 'SSH MCP',
    },
    clientIdMetadataDocumentEnabled: true,
    clientRegistrationEndpoint: '/oauth/register',
  };
}
