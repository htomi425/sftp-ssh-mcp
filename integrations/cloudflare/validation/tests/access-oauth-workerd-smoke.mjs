import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

async function bundle(name) {
  const result = await build({
    entryPoints: [new URL(name, import.meta.url).pathname],
    bundle: true, platform: 'browser', format: 'esm', target: 'es2022',
    external: ['cloudflare:*', 'node:*'], write: false,
  });
  return result.outputFiles[0].text;
}

const accessIssuer = 'https://test-team.cloudflareaccess.com';
const audience = 'a'.repeat(64);
const issuer = 'https://auth.example.invalid';
const resourceUrl = 'https://resource.example.invalid/mcp';
const redirectUri = 'https://client.example.invalid/callback';
const epoch = () => Math.floor(Date.now() / 1000);

function signingKey(kid) {
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { ...keys, jwk: { ...keys.publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } };
}

function accessToken(keys, extra = {}, header = {}) {
  const encode = data => Buffer.from(JSON.stringify(data)).toString('base64url');
  const input = encode({ alg: 'RS256', kid: keys.jwk.kid, ...header }) + '.' + encode({
    iss: accessIssuer, aud: [audience], sub: 'test-user', type: 'app', email: 'user@example.invalid',
    exp: epoch() + 180, iat: epoch() - 1, ...extra,
  });
  return input + '.' + sign('RSA-SHA256', Buffer.from(input), keys.privateKey).toString('base64url');
}

const firstKey = signingKey('1'.repeat(64));
const nextKey = signingKey('2'.repeat(64));
let publishedKeys = [firstKey.jwk];
const bindings = { OAUTH_CONSENT_SIGNING_SECRET: randomBytes(32).toString('base64url') };
const workerOptions = { modules: true, compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'] };
const authOptions = {
  ...workerOptions,
  script: await bundle('./access-oauth-auth-worker.mjs'),
  kvNamespaces: { OAUTH_KV: 'access-test' },
  bindings,
  outboundService(request) {
    assert.equal(request.url, accessIssuer + '/cdn-cgi/access/certs');
    return Response.json({ keys: publishedKeys });
  },
};
const mf = new Miniflare({ workers: [
  { ...authOptions, name: 'auth', durableObjects: { OAUTH_SUBJECT_STATE: 'OAuthSubjectState' } },
  { ...authOptions, name: 'auth-peer', durableObjects: {
    OAUTH_SUBJECT_STATE: { className: 'OAuthSubjectState', scriptName: 'auth' },
  }, serviceBindings: { TEST_ADMIN: { name: 'auth', entrypoint: 'TestAdmin' } } },
  { ...authOptions, name: 'auth-unavailable' },
  { ...workerOptions, name: 'resource', script: await bundle('./provider-worker-entry.mjs'),
    serviceBindings: { AUTH_SERVER: { name: 'auth-peer', entrypoint: 'AuthServer' } } },
  { ...workerOptions, name: 'resource-unavailable', script: await bundle('./provider-worker-entry.mjs'),
    serviceBindings: { AUTH_SERVER: { name: 'auth-unavailable', entrypoint: 'AuthServer' } } },
] });

try {
  const auth = await mf.getWorker('auth');
  const peer = await mf.getWorker('auth-peer');
  const unavailable = await mf.getWorker('auth-unavailable');
  const resource = await mf.getWorker('resource');
  const unavailableResource = await mf.getWorker('resource-unavailable');
  const { TEST_ADMIN: admin, OAUTH_SUBJECT_STATE: subjects, OAUTH_KV: kv } = await mf.getBindings('auth-peer');
  const subjectState = subjects.getByName(JSON.stringify([accessIssuer, 'test-user']));
  const metadataResponse = await auth.fetch(issuer + '/.well-known/oauth-authorization-server');
  assert.equal(metadataResponse.status, 200);
  const metadata = await metadataResponse.json();
  const registration = await auth.fetch(metadata.registration_endpoint, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'access-workerd-test', redirect_uris: [redirectUri],
      token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'] }),
  });
  assert.equal(registration.status, 201);
  const client = await registration.json();

  const verifier = randomBytes(48).toString('base64url');
  const requestUrl = new URL(metadata.authorization_endpoint);
  requestUrl.search = new URLSearchParams({
    response_type: 'code', client_id: client.client_id, redirect_uri: redirectUri, scope: 'mcp:invoke',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
    resource: resourceUrl,
  });
  const authorize = jwt => auth.fetch(requestUrl, { headers: jwt ? { 'Cf-Access-Jwt-Assertion': jwt } : {} });
  async function consent(jwt) {
    const response = await authorize(jwt);
    assert.equal(response.status, 200);
    const cookie = response.headers.get('Set-Cookie').split(';', 1)[0];
    const html = await response.text();
    const handle = html.match(/name="handle" value="([^"]+)"/)?.[1];
    assert.ok(handle);
    return { cookie, handle };
  }
  function approve({ cookie, handle }, jwt) {
    return auth.fetch(metadata.authorization_endpoint, { method: 'POST', redirect: 'manual',
      headers: { Cookie: cookie, 'Cf-Access-Jwt-Assertion': jwt, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ handle, decision: 'approve' }),
    });
  }
  async function codeFor(jwt) {
    const response = await approve(await consent(jwt), jwt);
    assert.equal(response.status, 302);
    return new URL(response.headers.get('Location')).searchParams.get('code');
  }
  function exchange(worker, fields) {
    return worker.fetch(metadata.token_endpoint, { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: client.client_id, ...fields }),
    });
  }
  const exchangeCode = code => exchange(auth, {
    grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: verifier,
  });
  const refresh = (worker, token) => exchange(worker, { grant_type: 'refresh_token', refresh_token: token });
  const invoke = (worker, token) => worker.fetch(resourceUrl, { headers: { Authorization: 'Bearer ' + token } });

  assert.equal((await authorize()).status, 401);
  for (const claims of [{ exp: epoch() - 1 }, { iss: 'https://other.example.invalid' }, { aud: ['other'] },
      { sub: '' }, { type: 'org' }, { common_name: 'service.access' }, { email: undefined }]) {
    assert.equal((await authorize(accessToken(firstKey, claims))).status, 401);
  }
  const badSignature = accessToken(nextKey, {}, { kid: firstKey.jwk.kid });
  assert.equal((await authorize(badSignature)).status, 401);
  const initialJwt = accessToken(firstKey);
  const initialConsent = await consent(initialJwt);
  assert.equal((await approve(initialConsent, accessToken(firstKey, { sub: 'other-user' }))).status, 403);
  publishedKeys = [nextKey.jwk];
  const rotatedJwt = accessToken(nextKey);
  const rotatedConsent = await consent(rotatedJwt);

  const shortJwt = accessToken(nextKey, { exp: epoch() + 45 });
  const tooShort = await exchangeCode(await codeFor(shortJwt));
  assert.equal(tooShort.status, 400);
  assert.equal((await tooShort.json()).error, 'invalid_grant');

  const initial = await exchangeCode(await codeFor(rotatedJwt));
  assert.equal(initial.status, 200);
  const tokens = await initial.json();
  assert.ok(tokens.expires_in >= 60 && tokens.expires_in <= 180);
  assert.equal((await invoke(resource, tokens.access_token)).status, 200);
  assert.equal((await invoke(unavailableResource, tokens.access_token)).status, 503);
  const badRefresh = await refresh(unavailable, tokens.refresh_token);
  assert.equal(badRefresh.status, 503);
  assert.equal((await badRefresh.json()).error, 'temporarily_unavailable');
  const refreshed = await refresh(peer, tokens.refresh_token);
  assert.equal(refreshed.status, 200);
  const updated = await refreshed.json();
  assert.notEqual(updated.refresh_token, tokens.refresh_token);
  assert.ok(updated.expires_in <= tokens.expires_in);

  // Check Durable Object revocation while the original token records are still in KV.
  await subjectState.setStopped(true);
  const providerId = createHash('sha256').update(JSON.stringify([accessIssuer, 'test-user'])).digest('hex');
  const grantPrefix = 'grant:' + providerId + ':';
  assert.ok((await kv.list({ prefix: grantPrefix })).keys.length);
  assert.equal((await invoke(resource, updated.access_token)).status, 401);
  await admin.setStopped('test-user', true);
  assert.equal((await kv.list({ prefix: grantPrefix })).keys.length, 0);
  const revoked = await refresh(peer, updated.refresh_token);
  assert.equal(revoked.status, 400);
  assert.equal((await revoked.json()).error, 'invalid_grant');
  assert.equal((await authorize(rotatedJwt)).status, 401);
  await admin.setStopped('test-user', false);
  assert.equal((await approve(rotatedConsent, rotatedJwt)).status, 403);
  assert.equal((await invoke(resource, updated.access_token)).status, 401);
  const renewed = await exchangeCode(await codeFor(accessToken(nextKey, { exp: epoch() + 86400 })));
  assert.equal(renewed.status, 200);
  assert.equal((await renewed.json()).expires_in, 600);
  console.log('Access JWT, OAuth PKCE, refresh, cross-Worker revocation and reauthorization verified');
} finally {
  await mf.dispose();
}
