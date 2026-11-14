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
      bindings: { TEST_ENABLE_AUTHORIZATION: 'enabled-for-local-tests-only' },
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
  const authorization = await auth.fetch(url, { redirect: 'manual' });
  assert.equal(authorization.status, 302, 'authorization code redirect');
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
    const initNode = await nodeRpc(initBody, initForward.assertion);
    assert.equal(initNode.status, 200, 'OAuth-authenticated MCP initialize reaches Node HTTP');
    assert.match(await initNode.text(), /SSH MCP Server/);
    const deniedBody = JSON.stringify({ jsonrpc: '2.0', id: 12, method: 'tools/call',
      params: { name: 'exec', arguments: { target: 'beta', command: 'echo forbidden' } } });
    const deniedGateway = await gateway.fetch(resourceUrl, {
      method: 'POST', headers: { Authorization: 'Bearer ' + token.access_token,
        'Content-Type': 'application/json', Accept: 'application/json' }, body: deniedBody,
    });
    assert.equal(deniedGateway.status, 200);
    const deniedForward = await deniedGateway.json();
    const deniedNode = await nodeRpc(deniedBody, deniedForward.assertion);
    assert.equal(deniedNode.status, 200, 'MCP authorization denial is an MCP response');
    assert.match(await deniedNode.text(), /access denied/i, 'OAuth user cannot execute on beta');
    assert.equal((await nodeRpc(deniedBody, deniedForward.assertion)).status, 401,
      'Node rejects replayed OAuth gateway assertion');
    assert.equal((await nodeRpc(deniedBody + ' ', deniedForward.assertion)).status, 401,
      'Node rejects tampered OAuth gateway request');
    console.log('Real OAuth -> workerd gateway -> Node HTTP MCP initialize and target denial passed');
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
