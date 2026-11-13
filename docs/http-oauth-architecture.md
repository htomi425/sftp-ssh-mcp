# HTTP authentication architecture (design, not implemented)

## Current state

The HTTP transport is loopback-only and accepts locally configured static bearer credentials via `SSH_MCP_HTTP_CREDENTIALS`. It does **not** implement OAuth 2.0, OAuth protected-resource metadata, token introspection, or JWT validation. Cloudflare Access authentication alone must not be mistaken for MCP OAuth authorization.

Do not publish the HTTP listener or claim OAuth compatibility before implementing and testing the following boundaries.

## Proposed architecture

1. **MCP client ↔ Cloudflare Access:** Cloudflare Access authenticates the incoming client at the edge. Browser sessions, service tokens, and Access application JWTs have different semantics. A successful Access login is not, by itself, an OAuth access token accepted by this MCP server.
2. **OAuth authorization server:** Choose an explicit OAuth authorization server compatible with MCP clients, supporting authorization-code + PKCE and discovery as needed. Define a stable protected-resource identifier and audience for the MCP endpoint.
3. **Cloudflare Tunnel ↔ local HTTP:** Tunnel forwards only to the loopback listener. Preserve the existing Cloudflare configuration until the new application and policy are separately tested.
4. **Token verification at MCP:** Validate signed access tokens using a trusted issuer's JWKS (or secure introspection for opaque tokens). Enforce issuer, audience, expiry, not-before, allowed algorithms, key rotation, and fail-closed behavior. Never trust arbitrary client-supplied identity headers. Never treat a Cloudflare Access JWT as an MCP OAuth access token without an explicit, validated trust contract.
5. **Authorization mapping:** Map the verified immutable subject (issuer + subject, or a verified service identity) to an explicit allowlist of SSH target names. Deny unknown identities and unknown targets. Never derive target permissions solely from token text or user-provided tool parameters.
6. **MCP HTTP semantics:** Provide OAuth protected-resource metadata and correct `WWW-Authenticate` discovery/challenge responses. Test a real MCP client through the entire login, refresh, and tool-call lifecycle, including insufficient scope and expired-token cases.

## Required security tests

- Invalid signature, issuer, audience, algorithm, expiry, or key ID is denied.
- A valid identity with no target mapping is denied.
- Identity A cannot select identity B's target, including the implicit/default target.
- Missing/invalid credentials fail closed and do not fall back to static tokens unless explicitly configured as a separate mode.
- Authorization metadata and client discovery work through the public HTTPS hostname.
- Client Origin/Host checks and proxy trust rules are explicitly defined; the current unconditional Origin rejection may need a narrowly scoped replacement for supported browser clients.
- Access tokens, OAuth refresh tokens, private SSH keys, and Cloudflare service credentials are never logged.
- HTTP upload/download of arbitrary **server-local paths** remains disabled; any future file transfer API must use an explicit safe data-transfer design.

## Decisions required before implementation

- OAuth authorization server/provider and whether it is managed by Cloudflare, a dedicated IdP, or another service.
- Whether MCP clients are interactive (browser-based login) or machine-to-machine, and whether both are needed.
- How verified identities map to target allowlists and where that policy is stored.
- Exact production MCP resource URL and metadata discovery URLs.

## Deployment gate

Do not change `main`, CT 200, Cloudflare Tunnel, DNS, or Access policies until the OAuth implementation and end-to-end verification are approved.
