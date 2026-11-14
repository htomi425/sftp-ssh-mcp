# Cloudflare resource gateway prototype (not deployable OAuth)

This optional module is **not** an OAuth authorization server, and it does not validate OAuth tokens itself. `resource-gateway.mjs` exposes `handleResourceRequest(request, env, verifyAccessToken, settings)`. The injected `verifyAccessToken` must be a trusted resource-server implementation that verifies an actual OAuth access token (issuer, resource/audience, expiration, scopes, revocation policy, signature or introspection). The current repository does **not** provide that implementation, OAuth discovery endpoints, PKCE login, client registration, refresh, or a deployable Worker entrypoint.

The gateway uses Web Crypto Ed25519 to sign a 30-second origin assertion covering `htm`, `htu`, and SHA-256 of the **raw** HTTP request bytes. The origin verifies the pinned public key, request binding and single-use `jti`, then resolves its local identity policy. Configure the origin mapping with issuer `GATEWAY_ISSUER` and subject `JSON.stringify([upstreamIssuer, upstreamSubject])`, not a user-controlled target list. The Worker strips caller-provided identity and proxy headers before forwarding.

The `ORIGIN` Service Binding must point to a private route reaching the Node.js loopback listener through an approved private connector/Tunnel architecture. The placeholder `https://origin.internal/mcp` is not a configured origin route. Do not expose the Node origin directly to the Internet or deploy the Worker before Service Binding reachability, token verification, metadata and end-to-end OAuth tests are implemented.

**Operational restrictions:** only one Node process with its in-memory replay cache; multiple processes need a shared atomic replay store. Keep the Ed25519 private key in Workers secrets and the public key at Node. Enforce resource scope and content size limits. Never log access tokens or assertions. The current gateway rejects browser Origin requests and does not yet support full OAuth client discovery. Existing Cloudflare configuration, CT 200, and `main` remain unchanged.

## OAuth Provider configuration scaffold

`oauth-provider-config.mjs` constructs the resource metadata and route options for the current `@cloudflare/workers-oauth-provider` `OAuthProvider` API, but **does not instantiate or deploy it**. The application must supply two distinct handlers: an authorization handler that calls `parseAuthRequest`, authenticates the human, obtains explicit consent, and only then calls `completeAuthorization`; and a protected API handler that obtains **verified provider token context**, checks `mcp:invoke`, and invokes the existing signed `handleResourceRequest` gateway with a trusted token verification adapter. The latter must not re-validate arbitrary bearer text using untrusted claims.

Provider storage requires `OAUTH_KV`. CIMD requires `global_fetch_strictly_public` and a compatible Workers compatibility date. Keep `/authorize`, `/oauth/token`, metadata, and client registration reachable for OAuth discovery rather than accidentally blocking them with a separate Access browser login. Configure production secrets and a private Service Binding separately after review. The configuration scaffold's tests verify routing/metadata and fail-closed requirements only; they do **not** test a live OAuth login, token refresh, Worker runtime, or the origin path.

Reference: https://github.com/cloudflare/workers-oauth-provider (provider API and deployment prerequisites).

## Workers OAuth Provider v1 split integration

Cloudflare's October 2026 v1 API uses **separate** `OAuthAuthorizationServer` and `OAuthResourceServer` instances. `oauth-provider-config.mjs` now returns two separate configuration objects; the older combined `OAuthProvider` options must not be used with them. The authorization Worker must implement login and explicit consent before calling `completeAuthorization`, and expose `validateToken` over its private Service Binding. The resource Worker supplies `validateToken: env => env.AUTH_SERVER.validateToken`.

`verified-resource-handler.mjs` receives the resource server's verified `ctx.auth` and `ctx.props`; it enforces `mcp:invoke` explicitly (the provider's `requiredScopes` is advertised, not enforced). Only after that check may its `forward` callback invoke `forwardVerifiedIdentity` from `resource-gateway.mjs`, which signs a fresh origin assertion. The `props.issuer` and `props.userId` fields must originate exclusively from the authorization Worker's trusted login/consent process, never client-provided input.

These are tested building blocks, **not** deployable Workers. The WorkerEntrypoint, login/consent UI, provider binding, provider KV storage, and OAuth end-to-end tests are still outstanding.

Cloudflare v1 reference: https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/

## Composed Worker modules

`authorization-worker.mjs` composes an `OAuthAuthorizationServer` v1 instance with `createAuthorizationHandler`, delegates discovery/token endpoints, and exposes `validateToken` for the private Service Binding. `resource-worker.mjs` composes `OAuthResourceServer`, validates through `env.AUTH_SERVER.validateToken`, explicitly checks `mcp:invoke`, and forwards verified identities using a fresh signed origin assertion.

These modules use dependency injection so unit tests can run without Cloudflare runtime. They **do not** establish a trusted login session, render a production consent page, provision the authorization server's storage, configure Service Bindings, or deploy a Worker. The `AUTH_SERVER` binding must be an authenticated, private service binding to the authorization Worker, not a client-controlled HTTP URL. Run the real Workers OAuth Provider runtime and browser/client OAuth end-to-end tests before production use.
