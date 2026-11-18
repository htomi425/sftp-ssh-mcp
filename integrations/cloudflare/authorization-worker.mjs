/**
 * Compose Workers OAuth Provider v1 authorization server with a trusted
 * login/consent handler. This module is dependency-injected to keep core CI
 * independent of Cloudflare runtime; the actual Worker entrypoint must supply
 * OAuthAuthorizationServer and an authenticated session implementation.
 */
import { createAuthorizationHandler } from './authorization-handler.mjs';

export function createAuthorizationWorker({
  authorizationServer,
  authenticateUser,
  renderConsent,
  bindConsent,
  prepareGrant,
}) {
  if (!authorizationServer ||
      typeof authorizationServer.getOAuthApi !== 'function' ||
      typeof authorizationServer.fetch !== 'function' ||
      typeof authorizationServer.validateToken !== 'function') {
    throw new Error('OAuthAuthorizationServer v1 instance required');
  }
  const authorization = createAuthorizationHandler({
    getOAuthApi: env => authorizationServer.getOAuthApi(env),
    authenticateUser,
    renderConsent,
    bindConsent,
    prepareGrant,
  });
  return {
    async fetch(request, env, ctx) {
      if (new URL(request.url).pathname === '/authorize') {
        return authorization.fetch(request, env);
      }
      return authorizationServer.fetch(request, env, ctx);
    },
    validateToken(resource, token, env) {
      return authorizationServer.validateToken(resource, token, env);
    },
  };
}

/**
 * Bind the authorization Worker to Cloudflare's WorkerEntrypoint RPC model.
 * A Service Binding invokes validateToken(resource, token) with no env argument;
 * the entrypoint supplies its own trusted this.env.
 */
export function createAuthorizationEntrypoint(WorkerEntrypoint, authorizationWorker) {
  if (typeof WorkerEntrypoint !== 'function' ||
      typeof authorizationWorker?.fetch !== 'function' ||
      typeof authorizationWorker?.validateToken !== 'function') {
    throw new Error('WorkerEntrypoint and authorization Worker required');
  }
  return class AuthServer extends WorkerEntrypoint {
    fetch(request) {
      return authorizationWorker.fetch(request, this.env, this.ctx);
    }
    validateToken(resource, token) {
      return authorizationWorker.validateToken(resource, token, this.env);
    }
  };
}
