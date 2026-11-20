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

const issuer = 'https://auth.example.invalid';
const googleIssuer = 'https://accounts.google.com';
const resourceUrl = 'https://resource.example.invalid/mcp';
const redirectUri = 'https://client.example.invalid/callback';
const googleCallback = issuer + '/google/callback';
const googleClientId = 'google-test-client';
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const first = { sub: '10001', email: 'one@gmail.com' };
const second = { sub: '10002', email: 'two@example.invalid', hd: 'example.invalid' };
const codes = new Map();
const hash = text => createHash('sha256').update(text).digest('base64url');
const epoch = () => Math.floor(Date.now() / 1000);

function googleToken(claims) {
  const encode = data => Buffer.from(JSON.stringify(data)).toString('base64url');
  const input = encode({ alg: 'RS256', kid: 'google-test-key' }) + '.' + encode({
    iss: googleIssuer, aud: googleClientId, iat: epoch(), exp: epoch() + 120,
    email_verified: true, ...claims,
  });
  return input + '.' + sign('RSA-SHA256', Buffer.from(input), keys.privateKey).toString('base64url');
}

const runtime = { modules: true, compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'] };
const mf = new Miniflare({ workers: [
  {
    ...runtime, name: 'auth', script: await bundle('./google-oauth-auth-worker.mjs'),
    kvNamespaces: { OAUTH_KV: 'google-oauth' },
    durableObjects: { OAUTH_SUBJECT_STATE: 'OAuthSubjectState', OAUTH_GOOGLE_FLOW: 'GoogleAuthorizationFlow' },
    bindings: {
      OAUTH_CONSENT_SIGNING_SECRET: randomBytes(32).toString('base64url'),
      GOOGLE_CLIENT_ID: googleClientId, GOOGLE_CLIENT_SECRET: 'mock-secret',
      GOOGLE_ALLOWED_EMAILS: 'one@gmail.com,two@example.invalid',
    },
    async outboundService(request) {
      if (request.url === 'https://www.googleapis.com/oauth2/v3/certs') {
        return Response.json({ keys: [
          { ...keys.publicKey.export({ format: 'jwk' }), kid: 'google-test-key', alg: 'RS256', use: 'sig' },
        ] });
      }
      assert.equal(request.url, 'https://oauth2.googleapis.com/token');
      assert.equal(request.method, 'POST');
      const form = new URLSearchParams(await request.text());
      const record = codes.get(form.get('code'));
      assert.ok(record);
      codes.delete(form.get('code'));
      assert.equal(hash(form.get('code_verifier')), record.params.get('code_challenge'));
      assert.equal(form.get('redirect_uri'), googleCallback);
      assert.equal(form.get('client_id'), googleClientId);
      assert.equal(form.get('client_secret'), 'mock-secret');
      if (record.redirect) return Response.redirect('https://example.invalid/', 302);
      return Response.json({ id_token: googleToken({ nonce: record.params.get('nonce'), ...record.claims }) });
    },
  },
  {
    ...runtime, name: 'resource', script: await bundle('./provider-worker-entry.mjs'),
    serviceBindings: { AUTH_SERVER: { name: 'auth', entrypoint: 'AuthServer' } },
  },
] });

try {
  const auth = await mf.getWorker('auth');
  const resource = await mf.getWorker('resource');
  const { OAUTH_SUBJECT_STATE: subjects } = await mf.getBindings('auth');
  const discovery = await auth.fetch(issuer + '/.well-known/oauth-authorization-server');
  assert.equal(discovery.status, 200);
  const metadata = await discovery.json();
  const registration = await auth.fetch(metadata.registration_endpoint, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'google-workerd-test', redirect_uris: [redirectUri],
      token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    }),
  });
  assert.equal(registration.status, 201);
  const client = await registration.json();

  const verifier = randomBytes(48).toString('base64url');
  const authorizeUrl = new URL(metadata.authorization_endpoint);
  authorizeUrl.search = new URLSearchParams({
    response_type: 'code', client_id: client.client_id, redirect_uri: redirectUri, scope: 'mcp:invoke',
    code_challenge: hash(verifier), code_challenge_method: 'S256', state: 'mcp-client-state',
    resource: resourceUrl,
  });
  let browserCookie;
  async function start() {
    const response = await auth.fetch(authorizeUrl, { redirect: 'manual',
      headers: browserCookie ? { Cookie: browserCookie } : {},
    });
    assert.equal(response.status, 302, await response.clone().text());
    const google = new URL(response.headers.get('Location'));
    assert.equal(google.origin, googleIssuer);
    const params = google.searchParams;
    assert.equal(params.get('redirect_uri'), googleCallback);
    assert.equal(params.get('prompt'), 'select_account');
    assert.equal(params.get('code_challenge_method'), 'S256');
    browserCookie = response.headers.get('Set-Cookie').split(';', 1)[0];
    return { params, cookie: browserCookie };
  }
  async function callback({ params, cookie }, claims, { state = params.get('state'), redirect = false } = {}) {
    const code = randomBytes(24).toString('hex');
    codes.set(code, { params, claims, redirect });
    const url = googleCallback + '?' + new URLSearchParams({ state, code });
    const response = await auth.fetch(url, { redirect: 'manual', headers: { Cookie: cookie } });
    codes.delete(code);
    if (response.status !== 303) return response;
    assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer');
    const next = new URL(response.headers.get('Location'), issuer);
    assert.equal(next.href, issuer + '/google/consent?state=' + state);
    return auth.fetch(next, { headers: { Cookie: cookie } });
  }
  async function consent(transaction, account) {
    const response = await callback(transaction, account);
    assert.equal(response.status, 200, await response.clone().text());
    assert.equal(response.headers.get('Referrer-Policy'), 'same-origin');
    const providerCookie = response.headers.get('Set-Cookie').split(';', 1)[0];
    const handle = (await response.text()).match(/name="handle" value="([^"]+)"/)?.[1];
    assert.ok(handle);
    return { providerCookie, handle };
  }
  function approve({ providerCookie, handle }, cookie = browserCookie) {
    return auth.fetch(metadata.authorization_endpoint, { method: 'POST', redirect: 'manual',
      headers: { Cookie: cookie + '; ' + providerCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ handle, decision: 'approve' }),
    });
  }
  function exchange(fields) {
    return auth.fetch(metadata.token_endpoint, { method: 'POST',
      body: new URLSearchParams({ client_id: client.client_id, ...fields }),
    });
  }
  async function tokensFor(consentForm) {
    const approved = await approve(consentForm);
    assert.equal(approved.status, 302, await approved.clone().text());
    const callbackUrl = new URL(approved.headers.get('Location'));
    assert.equal(callbackUrl.origin + callbackUrl.pathname, redirectUri);
    assert.equal(callbackUrl.searchParams.get('state'), 'mcp-client-state');
    const response = await exchange({
      grant_type: 'authorization_code', code: callbackUrl.searchParams.get('code'),
      redirect_uri: redirectUri, code_verifier: verifier,
    });
    assert.equal(response.status, 200, await response.clone().text());
    const tokens = await response.json();
    assert.ok(tokens.expires_in >= 60 && tokens.expires_in <= 120);
    return tokens;
  }
  const invoke = token => resource.fetch(resourceUrl, { headers: { Authorization: 'Bearer ' + token } });
  const subject = account => subjects.getByName(JSON.stringify([googleIssuer, account.sub]));

  assert.equal((await auth.fetch(googleCallback)).status, 400);
  assert.equal((await auth.fetch(metadata.authorization_endpoint, { redirect: 'manual' })).status, 400);
  const flow1 = await start();
  assert.equal((await callback(flow1, first, { state: 'wrong' })).status, 400);
  assert.equal((await callback({ ...flow1, cookie: flow1.cookie.replace(/\.[a-f0-9]{64}$/, '.' + '0'.repeat(64)) }, first)).status, 400);
  const initialForm = await consent(flow1, first);
  assert.equal((await callback(flow1, first)).status, 400);
  assert.equal((await approve(initialForm, 'unrelated=1')).status, 401);
  const firstTokens = await tokensFor(initialForm);
  assert.equal((await invoke(firstTokens.access_token)).status, 200);

  const repeated = await start();
  for (const param of ['state', 'nonce', 'code_challenge']) assert.notEqual(flow1.params.get(param), repeated.params.get(param));
  const repeatedForm = await consent(repeated, first);
  assert.equal((await approve(initialForm)).status, 403);
  const repeatedTokens = await tokensFor(repeatedForm);
  assert.equal((await invoke(repeatedTokens.access_token)).status, 200);

  const switched = await start();
  const switchedForm = await consent(switched, second);
  assert.equal((await approve(repeatedForm)).status, 403);
  const secondTokens = await tokensFor(switchedForm);
  assert.equal((await invoke(secondTokens.access_token)).status, 200);

  const refresh = token => exchange({ grant_type: 'refresh_token', refresh_token: token });
  const refreshResponse = await refresh(repeatedTokens.refresh_token);
  assert.equal(refreshResponse.status, 200);
  const refreshed = await refreshResponse.json();
  assert.notEqual(refreshed.refresh_token, repeatedTokens.refresh_token);
  await subject(first).setStopped(true);
  assert.equal((await invoke(refreshed.access_token)).status, 401);
  assert.equal((await invoke(secondTokens.access_token)).status, 200);
  assert.equal((await refresh(refreshed.refresh_token)).status, 400);
  assert.equal((await callback(await start(), first)).status, 401);
  await subject(first).setStopped(false);
  assert.equal((await invoke(refreshed.access_token)).status, 401);
  assert.equal((await invoke((await tokensFor(await consent(await start(), first))).access_token)).status, 200);

  for (const claims of [
    { ...first, nonce: 'wrong' }, { ...first, email_verified: false }, { ...first, azp: 'other' },
    { ...first, email: 'other@gmail.com' }, { ...second, hd: undefined },
  ]) {
    assert.equal((await callback(await start(), claims)).status, 403);
  }
  for (const claims of [{ ...first, aud: 'other' }, { ...first, exp: epoch() - 1 }]) {
    assert.equal((await callback(await start(), claims)).status, 503);
  }
  assert.equal((await callback(await start(), first, { redirect: true })).status, 502);
  console.log('Google account re-selection, consent isolation, MCP PKCE, token rotation and per-subject revocation verified');
} finally {
  await mf.dispose();
}
