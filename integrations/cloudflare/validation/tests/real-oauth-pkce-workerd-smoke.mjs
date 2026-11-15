import assert from 'node:assert/strict';
import { createHash, randomBytes, generateKeyPairSync, verify as verifySignature } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import { createGatewayAssertionVerifier } from '../../../../build/gateway-assertion.js';
import { createRequestBoundGatewayVerifier } from '../../../../build/gateway-request-binding.js';
import { createInMemoryReplayCache } from '../../../../build/gateway-replay.js';
import { parseIdentityTargetPolicy } from '../../../../build/identity-target-policy.js';
import { selectAuthorizedTarget } from '../../../../build/http-targets.js';
import { createAuthenticatedHttpServer, listenLoopback } from '../../../../build/http-server.js';
import { createGatewayHttpAuthenticator } from '../../../../build/gateway-http-auth.js';
import { createStreamableHttpHandler } from '../../../../build/http-mcp.js';
import { createToolServer } from '../../../../build/tool-server.js';

async function bundle(name) {
  const result = await build({
    entryPoints: [new URL(name, import.meta.url).pathname],
    bundle: true, platform: 'browser', format: 'esm', target: 'es2022',
    external: ['cloudflare:*', 'node:*'], write: false,
  });
  assert.equal(result.errors.length, 0);
  return result.outputFiles[0].text;
}

const issuer = 'https://auth.example.invalid';
const resourceUrl = 'https://resource.example.invalid/mcp';
const redirectUri = 'https://client.example.invalid/callback';
const gatewayKeys = generateKeyPairSync('ed25519');
const gatewayIssuer = 'https://gateway.example.invalid';
const gatewayAudience = 'ssh-mcp-origin';
const testSessionToken = 'S'.repeat(48);
const testSessionCookie = '__Host-ssh_mcp_session=' + testSessionToken;
const otherSessionToken = 'T'.repeat(48);
const otherSessionCookie = '__Host-ssh_mcp_session=' + otherSessionToken;
const mf = new Miniflare({
  workers: [
    {
      name: 'origin', modules: true,
      script: await bundle('./real-oauth-origin-capture-worker.mjs'),
      compatibilityDate: '2026-08-06',
    },
    {
      name: 'gateway', modules: true,
      script: await bundle('./real-oauth-resource-gateway-worker.mjs'),
      compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'],
      serviceBindings: {
        AUTH_SERVER: { name: 'auth', entrypoint: 'AuthServer' },
        ORIGIN: 'origin',
      },
      bindings: {
        GATEWAY_PRIVATE_KEY: gatewayKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
        GATEWAY_ISSUER: gatewayIssuer,
        GATEWAY_AUDIENCE: gatewayAudience,
      },
    },
    {
      name: 'auth', modules: true,
      script: await bundle('./real-oauth-auth-worker.mjs'),
      compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'],
      kvNamespaces: ['OAUTH_KV'],
      bindings: { TEST_ENABLE_AUTHORIZATION: 'enabled-for-local-tests-only',
        TEST_SESSION_TOKEN: testSessionToken,
        TEST_OTHER_SESSION_TOKEN: otherSessionToken },
    },
    {
      name: 'other-audience', modules: true,
      script: await bundle('./provider-other-audience-worker.mjs'),
      compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'],
      serviceBindings: { AUTH_SERVER: { name: 'auth', entrypoint: 'AuthServer' } },
    },
    {
      name: 'restricted', modules: true,
      script: await bundle('./provider-insufficient-scope-worker.mjs'),
      compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'],
      serviceBindings: { AUTH_SERVER: { name: 'auth', entrypoint: 'AuthServer' } },
    },
    {
      name: 'resource', modules: true,
      script: await bundle('./provider-worker-entry.mjs'),
      compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'],
      serviceBindings: { AUTH_SERVER: { name: 'auth', entrypoint: 'AuthServer' } },
    },
  ],
});
try {
  const auth = await mf.getWorker('auth');
  const resource = await mf.getWorker('resource');
  const restricted = await mf.getWorker('restricted');
  const otherAudience = await mf.getWorker('other-audience');
  const gateway = await mf.getWorker('gateway');
  const metadataResponse = await auth.fetch(issuer + '/.well-known/oauth-authorization-server');
  assert.equal(metadataResponse.status, 200, 'authorization discovery');
  const metadata = await metadataResponse.json();
  assert.ok(metadata.authorization_endpoint);
  assert.ok(metadata.token_endpoint);
  assert.ok(metadata.registration_endpoint);

  const registration = await auth.fetch(metadata.registration_endpoint, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'isolated-workerd-test', redirect_uris: [redirectUri],
      token_endpoint_auth_method: 'none', grant_types: ['authorization_code'],
      response_types: ['code'] }),
  });
  assert.ok(registration.ok, 'client registration: ' + registration.status + ' ' + await registration.clone().text().catch(() => ''));
  const client = await registration.json();
  assert.ok(client.client_id);

  const verifier = randomBytes(48).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(16).toString('base64url');
  const url = new URL(metadata.authorization_endpoint);
  for (const [key, value] of Object.entries({
    response_type: 'code', client_id: client.client_id, redirect_uri: redirectUri,
    code_challenge: challenge, code_challenge_method: 'S256', scope: 'mcp:invoke',
    resource: resourceUrl, state,
  })) url.searchParams.set(key, value);
  const unauthenticated = await auth.fetch(url, { redirect: 'manual' });
  assert.equal(unauthenticated.status, 401, 'authorization requires verified login session');
  const consentResponse = await auth.fetch(url, {
    headers: { Cookie: testSessionCookie }, redirect: 'manual',
  });
  assert.equal(consentResponse.status, 200, 'real provider must render consent before grant');
  const consentCookies = consentResponse.headers.getSetCookie().map(value => value.split(';', 1)[0]);
  assert.ok(consentCookies.length > 0, 'OAuth provider must bind consent to browser cookie');
  const consentHtml = await consentResponse.text();
  assert.match(consentHtml, /value="approve"/);
  assert.match(consentHtml, /value="deny"/);
  const consentHandle = consentHtml.match(/name="handle" value="([^"]+)"/)?.[1];
  assert.ok(consentHandle, 'real provider consent handle');
  // A separate browser consent must be explicitly denied without issuing a code.
  const denialConsent = await auth.fetch(url, {
    headers: { Cookie: testSessionCookie }, redirect: 'manual',
  });
  assert.equal(denialConsent.status, 200, 'denial flow consent page');
  const denialCookies = denialConsent.headers.getSetCookie().map(value => value.split(';', 1)[0]);
  assert.ok(denialCookies.length > 0, 'denial flow browser-binding cookie');
  const denialHtml = await denialConsent.text();
  const denialHandle = denialHtml.match(/name="handle" value="([^"]+)"/)?.[1];
  assert.ok(denialHandle, 'denial flow consent handle');
  const denial = await auth.fetch(issuer + '/authorize', {
    method: 'POST', redirect: 'manual',
    headers: { Cookie: [testSessionCookie, ...denialCookies].join('; '),
      'X-Test-Local-Origin': 'enabled-for-local-tests-only',
      'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ handle: denialHandle, decision: 'deny' }),
  });
  assert.equal(denial.status, 302, 'explicit denial must redirect to OAuth client');
  const deniedCallback = new URL(denial.headers.get('location'));
  assert.equal(deniedCallback.origin + deniedCallback.pathname, redirectUri);
  assert.equal(deniedCallback.searchParams.get('error'), 'access_denied');
  assert.equal(deniedCallback.searchParams.get('state'), state);
  assert.equal(deniedCallback.searchParams.has('code'), false, 'denial must not issue a code');
  // A stolen consent handle must not be usable from a different browser
  // even when the user is authenticated with the same test login session.
  const crossBrowserConsent = await auth.fetch(issuer + '/authorize', {
    method: 'POST', redirect: 'manual',
    headers: { Cookie: testSessionCookie,
      'X-Test-Local-Origin': 'enabled-for-local-tests-only',
      'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ handle: consentHandle, decision: 'approve' }),
  }).catch(error => error);
  assert.ok(crossBrowserConsent instanceof Error ||
    (crossBrowserConsent.status !== 302 && crossBrowserConsent.status !== 200),
    'consent handle must be bound to the originating browser');
  // Browser-bound consent must not bypass login: a missing authenticated
  // session is rejected even when the provider's consent cookie is present.
  const loggedOutConsent = await auth.fetch(issuer + '/authorize', {
    method: 'POST', redirect: 'manual',
    headers: { Cookie: consentCookies.join('; '),
      'X-Test-Local-Origin': 'enabled-for-local-tests-only',
      'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ handle: consentHandle, decision: 'approve' }),
  });
  assert.equal(loggedOutConsent.status, 401,
    'consent approval must require a live authenticated login session');
  // Switching to a different valid identity in the same browser must not
  // authorize the original user's pending consent.
  const switchedUserConsent = await auth.fetch(issuer + '/authorize', {
    method: 'POST', redirect: 'manual',
    headers: { Cookie: [otherSessionCookie, ...consentCookies].join('; '),
      'X-Test-Local-Origin': 'enabled-for-local-tests-only',
      'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ handle: consentHandle, decision: 'approve' }),
  }).catch(error => error);
  assert.ok(switchedUserConsent instanceof Error ||
    (switchedUserConsent.status !== 302 && switchedUserConsent.status !== 200),
    'consent initiated by one user must not be approved by a different logged-in user');
  const authorization = await auth.fetch(issuer + '/authorize', {
    method: 'POST', redirect: 'manual',
    headers: { Cookie: [testSessionCookie, ...consentCookies].join('; '),
      'X-Test-Local-Origin': 'enabled-for-local-tests-only',
      'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ handle: consentHandle, decision: 'approve' }),
  });
  assert.equal(authorization.status, 302, 'explicit consent authorization code redirect: ' +
    await authorization.clone().text() + ' diagnostic=' + JSON.stringify({
      requestOrigin: authorization.headers.get('X-Test-Request-Origin'),
      originHeader: authorization.headers.get('X-Test-Origin-Header'),
      hostHeader: authorization.headers.get('X-Test-Host-Header'),
    }));
  // The consent handle is single-use: replaying approval must not issue a second code.
  const replayedConsent = await auth.fetch(issuer + '/authorize', {
    method: 'POST', redirect: 'manual',
    headers: { Cookie: [testSessionCookie, ...consentCookies].join('; '),
      'X-Test-Local-Origin': 'enabled-for-local-tests-only',
      'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ handle: consentHandle, decision: 'approve' }),
  }).catch(error => error);
  assert.ok(replayedConsent instanceof Error ||
    (replayedConsent.status !== 302 && replayedConsent.status !== 200),
    'replayed consent handle must not issue another authorization');
  const callback = new URL(authorization.headers.get('location'));
  assert.equal(callback.origin + callback.pathname, redirectUri);
  assert.equal(callback.searchParams.get('state'), state);
  const code = callback.searchParams.get('code');
  assert.ok(code);

  const exchange = async (codeVerifier) => auth.fetch(metadata.token_endpoint, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id,
      redirect_uri: redirectUri, code, code_verifier: codeVerifier }),
  });
  const invalidExchange = await exchange('incorrect-pkce-verifier');
  assert.ok(!invalidExchange.ok, 'wrong PKCE verifier must be rejected');
  const tokenResponse = await exchange(verifier);
  assert.equal(tokenResponse.status, 200, 'valid PKCE exchange');
  const token = await tokenResponse.json();
  assert.ok(token.access_token);
  const accepted = await resource.fetch(resourceUrl, {
    method: 'POST', headers: { Authorization: 'Bearer ' + token.access_token,
      Accept: 'application/json' }, body: '{}',
  });
  assert.equal(accepted.status, 200, 'issued access token must pass resource validation');
  const gatewayBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  const gatewayResponse = await gateway.fetch(resourceUrl, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token.access_token,
      Accept: 'application/json', 'Content-Type': 'application/json',
      'X-User': 'forged-admin', 'X-Targets': 'forged-root' },
    body: gatewayBody,
  });
  assert.equal(gatewayResponse.status, 200, 'real OAuth resource worker forwards verified identity');
  const forwarded = await gatewayResponse.json();
  assert.equal(forwarded.body, gatewayBody);
  assert.equal(forwarded.method, 'POST');
  assert.equal(forwarded.path, '/mcp');
  const parts = forwarded.assertion.split('.');
  assert.equal(parts.length, 3);
  assert.equal(verifySignature(null, Buffer.from(parts[0] + '.' + parts[1]),
    gatewayKeys.publicKey, Buffer.from(parts[2], 'base64url')), true);
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(claims.iss, gatewayIssuer);
  assert.equal(claims.aud, gatewayAudience);
  assert.equal(claims.sub, JSON.stringify(['https://test-idp.example.invalid', 'test-user']));
  assert.equal(claims.htm, 'POST');
  assert.equal(claims.htu, '/mcp');
  assert.equal(claims.body_sha256, createHash('sha256').update(gatewayBody).digest('base64url'));
  // Validate the exact assertion produced from a real OAuth token with the Node
  // origin's production verifier, replay cache and identity-to-target policy.
  const originVerifier = createGatewayAssertionVerifier({
    issuer: gatewayIssuer, audience: gatewayAudience,
    publicKeyPem: gatewayKeys.publicKey.export({ type: 'spki', format: 'pem' }),
  });
  const boundVerifier = createRequestBoundGatewayVerifier(originVerifier, createInMemoryReplayCache());
  const requestBinding = { method: 'POST', path: '/mcp', body: Buffer.from(gatewayBody) };
  const verifiedIdentity = boundVerifier.verifyOnce(forwarded.assertion, requestBinding);
  const targetRegistry = {
    alpha: { host: '127.0.0.1', user: 'tester', password: 'unused', hostKeySha256: 'a'.repeat(64) },
    beta: { host: '127.0.0.2', user: 'tester', password: 'unused', hostKeySha256: 'b'.repeat(64) },
  };
  const identityPolicy = parseIdentityTargetPolicy(JSON.stringify([{
    issuer: gatewayIssuer,
    subject: JSON.stringify(['https://test-idp.example.invalid', 'test-user']),
    targets: ['alpha'],
  }]), new Set(Object.keys(targetRegistry)));
  const principal = identityPolicy.resolve(verifiedIdentity);
  assert.equal(principal.targets.has('alpha'), true);
  assert.equal(principal.targets.has('beta'), false);
  assert.ok(selectAuthorizedTarget(targetRegistry, principal, 'alpha'));
  assert.throws(() => selectAuthorizedTarget(targetRegistry, principal, 'beta'), /access denied/i,
    'real OAuth user must not gain access to unassigned SSH target');
  assert.throws(() => boundVerifier.verifyOnce(forwarded.assertion, requestBinding),
    'gateway assertion replay must be denied');
  assert.throws(() => createRequestBoundGatewayVerifier(originVerifier, createInMemoryReplayCache())
    .verifyOnce(forwarded.assertion, { ...requestBinding, body: Buffer.from(gatewayBody + ' ') }),
    'gateway assertion must not authenticate a modified body');
  // Real HTTP MCP server: use a fresh assertion from the OAuthResourceServer
  // and pass the exact bytes into Node's production authentication boundary.
  const httpAuth = createGatewayHttpAuthenticator(originVerifier, createInMemoryReplayCache(), identityPolicy);
  const nodeServer = createAuthenticatedHttpServer(httpAuth,
    createStreamableHttpHandler(user => createToolServer(targetRegistry, { principal: user }, 'http')));
  const { port } = await listenLoopback(nodeServer, '127.0.0.1', 0);
  const nodeUrl = 'http://127.0.0.1:' + port + '/mcp';
  async function nodeRpc(body, assertion) {
    return fetch(nodeUrl, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + assertion,
        'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body,
    });
  }
  try {
    const initBody = JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {},
        clientInfo: { name: 'real-oauth-node-test', version: '1' } } });
    const initGateway = await gateway.fetch(resourceUrl, {
      method: 'POST', headers: { Authorization: 'Bearer ' + token.access_token,
        'Content-Type': 'application/json', Accept: 'application/json' }, body: initBody,
    });
    assert.equal(initGateway.status, 200);
    const initForward = await initGateway.json();
    // The same valid OAuth token and correctly signed assertion must be
    // rejected by a Node origin whose local allowlist omits this identity.
    const unmappedPolicy = parseIdentityTargetPolicy(JSON.stringify([{
      issuer: gatewayIssuer,
      subject: JSON.stringify(['https://test-idp.example.invalid', 'different-user']),
      targets: ['alpha'],
    }]), new Set(Object.keys(targetRegistry)));
    const unmappedServer = createAuthenticatedHttpServer(
      createGatewayHttpAuthenticator(originVerifier, createInMemoryReplayCache(), unmappedPolicy),
      createStreamableHttpHandler(user => createToolServer(targetRegistry, { principal: user }, 'http')));
    const unmappedAddress = await listenLoopback(unmappedServer, '127.0.0.1', 0);
    try {
      const unmappedResponse = await fetch('http://127.0.0.1:' + unmappedAddress.port + '/mcp', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + initForward.assertion,
          'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
        body: initBody,
      });
      assert.equal(unmappedResponse.status, 401,
        'valid OAuth token and gateway signature cannot bypass Node identity allowlist');
    } finally {
      await new Promise((resolve, reject) =>
        unmappedServer.close(error => error ? reject(error) : resolve()));
    }
    const initNode = await nodeRpc(initBody, initForward.assertion);
    assert.equal(initNode.status, 200, 'OAuth-authenticated MCP initialize reaches Node HTTP');
    assert.match(await initNode.text(), /SSH MCP Server/);
    // Every exposed SSH/SFTP tool must enforce the same per-principal target
    // boundary, even when the OAuth token and gateway assertion are valid.
    for (const [name, args] of [
      ['exec', { target: 'beta', command: 'echo forbidden' }],
      ['sftp_list', { target: 'beta', remotePath: '/tmp' }],
      ['sftp_upload', { target: 'beta', localPath: '/etc/passwd', remotePath: '/tmp/blocked' }],
      ['sftp_download', { target: 'beta', remotePath: '/etc/passwd', localPath: '/tmp/blocked' }],
    ]) {
      const deniedBody = JSON.stringify({ jsonrpc: '2.0', id: 12, method: 'tools/call',
        params: { name, arguments: args } });
      const deniedGateway = await gateway.fetch(resourceUrl, {
        method: 'POST', headers: { Authorization: 'Bearer ' + token.access_token,
          'Content-Type': 'application/json', Accept: 'application/json' }, body: deniedBody,
      });
      assert.equal(deniedGateway.status, 200, name + ': OAuth gateway forwarding');
      const deniedForward = await deniedGateway.json();
      const deniedNode = await nodeRpc(deniedBody, deniedForward.assertion);
      assert.equal(deniedNode.status, 200, name + ': MCP authorization denial response');
      assert.match(await deniedNode.text(), /access denied/i,
        name + ': OAuth user cannot access unassigned beta target');
      assert.equal((await nodeRpc(deniedBody, deniedForward.assertion)).status, 401,
        name + ': Node rejects replayed OAuth gateway assertion');
      assert.equal((await nodeRpc(deniedBody + ' ', deniedForward.assertion)).status, 401,
        name + ': Node rejects tampered OAuth gateway request');
    }
    console.log('Real OAuth -> workerd gateway -> Node HTTP MCP initialize and all four tool target denials passed');
  } finally {
    await new Promise((resolve, reject) => nodeServer.close(error => error ? reject(error) : resolve()));
  }
  const gatewayRejected = await gateway.fetch(resourceUrl, {
    method: 'POST', headers: { Authorization: 'Bearer invalid-token', Accept: 'application/json' },
    body: gatewayBody,
  });
  assert.equal(gatewayRejected.status, 401, 'invalid OAuth token must not reach origin');
  const restrictedResponse = await restricted.fetch(resourceUrl, {
    method: 'POST', headers: { Authorization: 'Bearer ' + token.access_token,
      Accept: 'application/json' }, body: '{}',
  });
  assert.equal(restrictedResponse.status, 403, 'valid token without mcp:admin must be denied');
  assert.match(restrictedResponse.headers.get('www-authenticate') || '', /insufficient_scope/i);
  const wrongAudience = await otherAudience.fetch('https://other-resource.example.invalid/mcp', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token.access_token,
      Accept: 'application/json' },
    body: '{}',
  });
  assert.equal(wrongAudience.status, 401,
    'valid OAuth token must not authenticate a different protected resource');
  const wrongResource = await resource.fetch('https://resource.example.invalid/other', {
    method: 'POST', headers: { Authorization: 'Bearer ' + token.access_token }, body: '{}',
  });
  assert.notEqual(wrongResource.status, 200, 'token cannot access unrelated path');
  const replay = await exchange(verifier);
  assert.ok(!replay.ok, 'authorization code replay must fail');
  console.log('Real OAuth PKCE code exchange, token acceptance, signed gateway forwarding, Node identity-target enforcement, scope rejection and code replay rejection passed');
} finally {
  await mf.dispose();
}
