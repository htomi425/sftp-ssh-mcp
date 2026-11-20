import assert from 'node:assert/strict';
import test from 'node:test';
import { createAccessGrantPolicy } from '../integrations/cloudflare/access-grants.mjs';

test('enforces absolute grant expiry even if the provider still accepts the token', async t => {
  let now = 1_800_000_000;
  t.mock.method(Date, 'now', () => now * 1000);
  const state = { generation: 0, stopped: false };
  const env = { OAUTH_SUBJECT_STATE: { getByName: () => ({ read: async () => state }) } };
  class OAuthError extends Error {
    constructor(code) {
      super(code);
      this.code = code;
    }
  }
  const issuer = 'https://team.cloudflareaccess.com';
  const policy = createAccessGrantPolicy({
    authenticateAccessUser: async () => ({ id: 'subject', issuer, expiresAt: now + 86400 * 7 }),
    OAuthError,
  });
  const user = await policy.authenticateUser(new Request(issuer), env);
  const { props } = await policy.prepareGrant(user, env);
  assert.equal(props.expiresAt, now + 86400 * 3);
  const exchange = grantType => policy.tokenExchangeCallback({ grantType, props, env });
  assert.deepEqual(await exchange('authorization_code'), {
    accessTokenTTL: 600, refreshTokenTTL: 86400 * 3,
  });
  const provider = { validateToken: async () => ({ props, expiresAt: props.expiresAt + 1 }) };
  const resource = 'https://resource.example.invalid/mcp';
  const validate = () => policy.validateToken(provider, resource, 'opaque', env);
  now = props.expiresAt - 60;
  assert.deepEqual(await exchange('refresh_token'), { accessTokenTTL: 60, refreshTokenTTL: undefined });
  now++;
  await assert.rejects(exchange('refresh_token'), { code: 'invalid_grant' });
  assert.equal((await validate()).expiresAt, props.expiresAt);
  now = props.expiresAt;
  assert.equal(await validate(), null);
});
