# Cloudflare OAuth prototype (not production-deployable)

This optional module is **not** an OAuth authorization server, and it does not validate OAuth tokens itself. `resource-gateway.mjs` exposes `handleResourceRequest(request, env, verifyAccessToken, settings)`. The injected `verifyAccessToken` must be a trusted resource-server implementation that verifies an actual OAuth access token (issuer, resource/audience, expiration, scopes, revocation policy, signature or introspection). The repository also contains separate Workers OAuth Provider v1 authorization/resource integrations and isolated Miniflare tests for OAuth discovery, dynamic client registration, PKCE authorization-code exchange and verified resource requests. The standalone `handleResourceRequest` adapter itself is not an OAuth token validator; the integration must use trusted provider validation through the private Service Binding. There is no production-deployed Worker entrypoint or verified end-to-end Cloudflare Tunnel route.

The gateway uses Web Crypto Ed25519 to sign a 30-second origin assertion covering `htm`, `htu`, and SHA-256 of the **raw** HTTP request bytes. The origin verifies the pinned public key, request binding and single-use `jti`, then resolves its local identity policy. Configure the origin mapping with issuer `GATEWAY_ISSUER` and subject `JSON.stringify([upstreamIssuer, upstreamSubject])`, not a user-controlled target list. The Worker strips caller-provided identity and proxy headers before forwarding.

The `ORIGIN` Service Binding must point to a private route reaching the Node.js loopback listener through an approved private connector/Tunnel architecture. The placeholder `https://origin.internal/mcp` is not a configured origin route. Do not expose the Node origin directly to the Internet or deploy the Worker before private origin reachability, real IdP session verification and production configuration are implemented and validated.

**Operational restrictions:** only one Node process with its in-memory replay cache; multiple processes need a shared atomic replay store. Keep the Ed25519 private key in Workers secrets and the public key at Node. Enforce resource scope and content size limits. Never log access tokens or assertions. The gateway rejects browser Origin requests; OAuth discovery is supplied by the separate provider integration, not the raw gateway adapter. Existing Cloudflare configuration, CT 200, and `main` remain unchanged.

## OAuth Provider configuration scaffold

`oauth-provider-config.mjs` constructs the resource metadata and route options for the `@cloudflare/workers-oauth-provider` v1 split API, but **does not instantiate or deploy it**. The application must supply two distinct handlers: an authorization handler that calls `parseAuthRequest`, authenticates the human, obtains explicit consent, and only then calls `completeAuthorization`; and a protected API handler that obtains **verified provider token context**, checks `mcp:invoke`, and invokes the signed `forwardVerifiedIdentity` gateway after provider validation. The latter must not re-validate arbitrary bearer text using untrusted claims.

Provider storage requires `OAUTH_KV`. CIMD requires `global_fetch_strictly_public` and a compatible Workers compatibility date. Protect the exact `/authorize` path with Access. Keep the authorization server metadata, token exchange, client registration and OAuth-protected resource available to MCP clients without an Access browser session. Configure production secrets and a private Service Binding separately after review. The configuration-scaffold unit tests verify metadata and fail-closed requirements; separate Miniflare/workerd tests exercise real provider discovery, registration, consent, PKCE, resource validation, signed gateway assertions and a test-only Node origin bridge. They do not establish a real IdP login, production Tunnel reachability or token refresh behavior.

Reference: https://github.com/cloudflare/workers-oauth-provider (provider API and deployment prerequisites).

## Workers OAuth Provider v1 split integration

Cloudflare's October 2026 v1 API uses **separate** `OAuthAuthorizationServer` and `OAuthResourceServer` instances. `oauth-provider-config.mjs` now returns two separate configuration objects; the older combined `OAuthProvider` options must not be used with them. The authorization Worker must implement login and explicit consent before calling `completeAuthorization`, and expose `validateToken` over its private Service Binding. The resource Worker supplies `validateToken: env => env.AUTH_SERVER.validateToken`.

`verified-resource-handler.mjs` receives the resource server's verified `ctx.auth` and `ctx.props`; it enforces `mcp:invoke` explicitly (the provider's `requiredScopes` is advertised, not enforced). Only after that check may its `forward` callback invoke `forwardVerifiedIdentity` from `resource-gateway.mjs`, which signs a fresh origin assertion. The `props.issuer` and `props.userId` fields must originate exclusively from the authorization Worker's trusted login/consent process, never client-provided input.

These are tested building blocks, **not** deployable production Workers. WorkerEntrypoint, consent UI, OAuth KV and Service Binding are exercised in isolated workerd tests, including PKCE and a test-only origin bridge. Production IdP login, secret provisioning, real private origin connectivity and deployment manifests remain outstanding.

Cloudflare v1 reference: https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/

## Composed Worker modules

`authorization-worker.mjs` composes an `OAuthAuthorizationServer` v1 instance with `createAuthorizationHandler`, delegates discovery/token endpoints, and exposes `validateToken` for the private Service Binding. `resource-worker.mjs` composes `OAuthResourceServer`, validates through `env.AUTH_SERVER.validateToken`, explicitly checks `mcp:invoke`, and forwards verified identities using a fresh signed origin assertion.

These modules use dependency injection so unit tests can run without Cloudflare runtime. They **do not** establish a production IdP-backed login session, provision production secrets or storage, configure deployed Service Bindings, or deploy a Worker. A consent page exists and is covered by isolated tests. The `AUTH_SERVER` binding must be an authenticated, private service binding to the authorization Worker, not a client-controlled HTTP URL. The real provider runs under Miniflare in CI; validate production IdP/session, deployment network topology and real browser/client behavior before production use.

## Isolated real-provider validation

`validation/package.json` contains an independent dependency on `@cloudflare/workers-oauth-provider` v1. The main CI workflow also runs a `cloudflare-oauth-provider` job with bundling, real Miniflare/workerd provider flows, private Service Binding and OAuth-to-test-origin checks. The separate manually triggered `.github/workflows/cloudflare-oauth-validation.yml` is a legacy isolated validation workflow; do not treat its presence as evidence of deployment. Tests do not alter CT 200 or Cloudflare production settings. The OAuth Provider version is pinned and locked in the isolated validation package.

The passing Miniflare/workerd integration tests demonstrate the isolated provider flow, not a real upstream IdP session, browser interoperability, token refresh, Cloudflare Tunnel connectivity or deployment readiness. Deployment requires explicit approval.


## Consent identity binding and production secret requirements (November 2026)

The isolated real-provider/Miniflare PKCE tests now exercise explicit consent, denial, replay protection, stolen handles without the browser-bound provider cookie, lost login sessions, and switching from one authenticated subject to another in the same browser. The authorization flow uses `createConsentIdentityBinding` to HMAC-SHA256-sign the provider consent handle together with the verified login `issuer`, `subject` and a ten-minute expiry. Both approve and deny verify this identity binding before invoking the provider. The provider's own browser-bound consent cookie remains mandatory.

**Production integration:** `createConsentAuthorizationWorker({ authorizationServer, verifySession, consentSigningSecret })` requires an independently verified login session and a high-entropy signing secret. Supply the secret using a Cloudflare Workers secret binding, not a checked-in value or a public `vars` field. The composition function takes the actual secret value, so instantiate it using the trusted environment at Worker request handling or another secure initialization point. Generate at least 32 cryptographically random bytes with a CSPRNG, encode them as canonical unpadded base64url (43 characters) and store the encoded value as the secret binding. The environment-backed wrapper enforces this encoding and decoded length, but no parser can prove randomness from the encoded string. The environment-backed wrapper decodes this representation and uses the original 32 bytes as its HMAC-SHA256 key. Keep the same secret available across Worker instances, rotate with an explicit strategy (old in-flight consent forms will be invalidated if the secret changes), and never log it or the signed handle.

**Not production-ready:** the Miniflare authorization Worker uses a fixed **test-only** signing secret and a synthetic session verifier. It must never be deployed. A real IdP-backed login, secure session issuance and revocation, secret provisioning, origin connectivity, deployment manifests and an operational key-rotation plan remain required. The passing tests do not establish Cloudflare Tunnel reachability or production readiness.

### Environment-secret authorization composition

For a Workers deployment, prefer `createEnvConsentAuthorizationWorker({ authorizationServer, verifySession })` over constructing a module-scope authorization Worker with a literal key. Its default secret-binding name is `OAUTH_CONSENT_SIGNING_SECRET`; configure that value as a **Workers secret**, never as a public variable or in source control. This wrapper reads the secret from the trusted Worker `env` on each `/authorize` request, requires canonical base64url encoding of exactly 32 bytes (43 characters), and responds with HTTP 503 and `Cache-Control: no-store` if it is absent or invalid. Discovery/token routes and the private `validateToken` Service Binding still delegate to the real OAuth provider. The login verifier remains supplied by the deployment and must validate an actual IdP-backed session. This convenience wrapper is not an entire deployable OAuth configuration.

### Cloudflare Access login and grant lifetime

Use `createAccessAuthorizationWorker({ OAuthAuthorizationServer, OAuthError, providerOptions, access })`
with Workers OAuth Provider 1.2.4. Set `access.issuer` to the exact HTTPS team origin
and `access.audience` to the protected application's AUD tag. Configure a user
Access policy for the authorization path and use the existing
`OAUTH_CONSENT_SIGNING_SECRET` and `OAUTH_KV` bindings. Export the class returned by
`createOAuthSubjectState(DurableObject)` and bind it privately as
`OAUTH_SUBJECT_STATE`. Point the resource Worker's private `AUTH_SERVER` binding
at `createAuthorizationEntrypoint(WorkerEntrypoint, worker)` so resource requests
use the same grant policy as token exchange.

The Access assertion is verified with the team signing keys. The grant ends at
the earlier of three days after approval or the signed Access expiry. Access
tokens have a ten-minute maximum. Exchanges require at least 60 seconds
remaining, which is the Provider's minimum token TTL. Resource validation uses
the stored absolute grant expiry independently of OAuth KV expiry.

Call `worker.setSubjectStopped(env, subject, stopped)` from trusted
administration code. Stopping a subject invalidates their old generation before
cleaning up matching OAuth KV grants. Retry the stop operation if KV cleanup
fails. Re-enabling the subject requires a new consent grant. Use the signed
Access `sub` as the subject and configure Node's identity mapping with the Access
team issuer and that subject according to the existing gateway format.

Run `npm run check:real-oauth-pkce --prefix integrations/cloudflare/validation`
after building the repository and installing the isolated validation dependencies.
The Access test uses locally signed JWTs and workerd with a separate authorization
and resource Worker, private Service Bindings, shared Durable Object state and
OAuth KV. Deployment manifests, real Access/IdP login and the production Tunnel
route are tracked in the [session design](../../docs/cloudflare-oauth-session.md).
