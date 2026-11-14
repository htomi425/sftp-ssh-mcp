/**
 * OAuthResourceServer v1 adapter. The OAuth provider validates access tokens
 * using the private authorization-server Service Binding before calling
 * the handler. Its requiredScopes is only advisory; the handler enforces it.
 */
import { createVerifiedResourceHandler } from './verified-resource-handler.mjs';
import { forwardVerifiedIdentity } from './resource-gateway.mjs';

export function createResourceWorker({
  OAuthResourceServer,
  insufficientScope,
  resourceUrl,
  authorizationServerUrl,
  requiredScope = 'mcp:invoke',
}) {
  if (typeof OAuthResourceServer !== 'function' || typeof insufficientScope !== 'function') {
    throw new Error('OAuthResourceServer v1 and insufficientScope required');
  }
  for (const value of [resourceUrl, authorizationServerUrl]) {
    if (typeof value !== 'string' || !value.startsWith('https://')) {
      throw new Error('HTTPS OAuth URLs required');
    }
  }
  const handler = createVerifiedResourceHandler({
    requiredScope,
    insufficientScope,
    forward: (request, env, identity) => forwardVerifiedIdentity(request, env, identity, {
      resource: resourceUrl, requiredScope,
    }),
  });
  return new OAuthResourceServer({
    resourceMetadata: {
      resource: resourceUrl,
      authorization_servers: [authorizationServerUrl],
    },
    requiredScopes: [requiredScope],
    validateToken: env => {
      if (!env.AUTH_SERVER || typeof env.AUTH_SERVER.validateToken !== 'function') {
        throw new Error('Private authorization Service Binding required');
      }
      return env.AUTH_SERVER.validateToken;
    },
    handler,
  });
}
