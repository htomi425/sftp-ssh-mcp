/**
 * Configuration inputs for Workers OAuth Provider v1's SPLIT API.
 * Instantiate OAuthAuthorizationServer and OAuthResourceServer in separate
 * Workers. This factory does not perform login, consent or token validation.
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
  const scope = 'mcp:invoke';
  return {
    authorization: {
      issuer: issuer.origin,
      resources: [resource.href],
      scopesSupported: [scope],
      clientIdMetadataDocumentEnabled: true,
      clientRegistrationEndpoint: '/oauth/register',
    },
    resource: {
      resourceMetadata: {
        resource: resource.href,
        authorization_servers: [issuer.origin],
        scopes_supported: [scope],
      },
      requiredScopes: [scope],
      // OAuthResourceServer validates through the private AUTH_SERVER binding.
      // Caller must supply validateToken: env => env.AUTH_SERVER.validateToken.
      handler: resourceHandler,
    },
    authorizationHandler,
  };
}
