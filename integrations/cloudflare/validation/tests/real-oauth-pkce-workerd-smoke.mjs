import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

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
const mf = new Miniflare({
  workers: [
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
  console.log('Real OAuth PKCE code exchange, token acceptance, scope rejection and code replay rejection passed');
} finally {
  await mf.dispose();
}
