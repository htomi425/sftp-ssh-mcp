import assert from 'node:assert/strict';
import { test } from 'node:test';
import { renderOAuthConsent } from '../integrations/cloudflare/consent-ui.mjs';
import { createSessionAuthenticator } from '../integrations/cloudflare/session-auth.mjs';

test('consent page escapes client and handle, renders explicit decisions and prevents caching', async () => {
  const response = renderOAuthConsent({
    details: { client: { client_name: '<script>alert(1)</script>' }, scope: ['mcp:invoke'] },
    consent: { handle: 'abc" onfocus="alert(1)' },
  });
  const html = await response.text();
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /abc&quot; onfocus=&quot;alert/);
  assert.match(html, /value="approve"/);
  assert.match(html, /value="deny"/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.headers.get('content-security-policy'), /form-action 'self'/);
  assert.throws(() => renderOAuthConsent({ consent: { handle: '' } }));
});

test('session adapter rejects absent, duplicated, malformed and unverified cookies', async () => {
  const token = 'A'.repeat(48);
  const seen = [];
  const auth = createSessionAuthenticator({
    verifySession: async value => { seen.push(value); return value === token
      ? { id: 'alice', issuer: 'https://login.example' } : null; },
  });
  const request = cookie => new Request('https://auth.example/authorize', {
    headers: cookie === null ? {} : { Cookie: cookie },
  });
  assert.equal(await auth(request(null), {}), null);
  assert.equal(await auth(request('__Host-ssh_mcp_session=short'), {}), null);
  assert.equal(await auth(request('__Host-ssh_mcp_session=' + token + '; __Host-ssh_mcp_session=' + token), {}), null);
  assert.deepEqual(await auth(request('__Host-ssh_mcp_session=' + token), {}),
    { id: 'alice', issuer: 'https://login.example' });
  assert.deepEqual(seen, [token]);
  assert.throws(() => createSessionAuthenticator({ verifySession: () => null, cookieName: 'session' }));
});
