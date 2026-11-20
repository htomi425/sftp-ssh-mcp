const maxGrantLifetime = 3 * 24 * 60 * 60;
const maxAccessLifetime = 10 * 60;
const minProviderLifetime = 60;
const encoder = new TextEncoder();
const initialState = { generation: 0, stopped: false };
const currentTime = () => Math.floor(Date.now() / 1000);

function subjectStore(env, issuer, subject) {
  return env.OAUTH_SUBJECT_STATE.getByName(JSON.stringify([issuer, subject]));
}

async function providerUserId(issuer, subject) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(JSON.stringify([issuer, subject])));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

export function createOAuthSubjectState(DurableObject) {
  return class OAuthSubjectState extends DurableObject {
    async read() {
      return (await this.ctx.storage.get('state')) ?? initialState;
    }

    async setStopped(stopped) {
      if (typeof stopped !== 'boolean') throw new TypeError('Boolean subject state required');
      return this.ctx.storage.transaction(async storage => {
        const current = (await storage.get('state')) ?? initialState;
        if (current.stopped === stopped) return current;
        const state = { generation: current.generation + Number(stopped), stopped };
        await storage.put('state', state);
        return state;
      });
    }
  };
}

export function createAccessGrantPolicy({ authenticateAccessUser, OAuthError }) {
  async function isCurrent(props, env) {
    if (!props || typeof props.issuer !== 'string' || !props.issuer ||
        typeof props.userId !== 'string' || !props.userId ||
        !Number.isSafeInteger(props.expiresAt) || props.expiresAt <= currentTime() ||
        !Number.isSafeInteger(props.generation) || props.generation < 0) return false;
    const state = await subjectStore(env, props.issuer, props.userId).read();
    return state.stopped === false && state.generation === props.generation &&
      props.expiresAt > currentTime();
  }

  return {
    async authenticateUser(request, env) {
      const user = await authenticateAccessUser(request, env);
      if (!user) return null;
      const state = await subjectStore(env, user.issuer, user.id).read();
      return state.stopped === false && Number.isSafeInteger(state.generation) &&
        user.expiresAt > currentTime() ? { ...user, generation: state.generation } : null;
    },

    async prepareGrant(user, env) {
      const props = {
        userId: user.id,
        issuer: user.issuer,
        expiresAt: Math.min(user.expiresAt, currentTime() + maxGrantLifetime),
        generation: user.generation,
      };
      if (!await isCurrent(props, env)) return null;
      return {
        userId: await providerUserId(user.issuer, user.id),
        metadata: { generation: user.generation },
        props,
      };
    },

    async tokenExchangeCallback({ grantType, props, env }) {
      if (grantType !== 'authorization_code' && grantType !== 'refresh_token') {
        throw new OAuthError('unsupported_grant_type', { description: 'Unsupported grant type' });
      }
      let valid;
      try {
        valid = await isCurrent(props, env);
      } catch {
        throw new OAuthError('temporarily_unavailable', {
          description: 'Authorization state unavailable', statusCode: 503,
        });
      }
      const remaining = valid ? props.expiresAt - currentTime() : 0;
      if (remaining < minProviderLifetime) {
        throw new OAuthError('invalid_grant', { description: 'Authorization has expired or been revoked' });
      }
      return {
        accessTokenTTL: Math.min(remaining, maxAccessLifetime),
        refreshTokenTTL: grantType === 'authorization_code' ? remaining : undefined,
      };
    },

    async validateToken(provider, resource, token, env) {
      const validated = await provider.validateToken(resource, token, env);
      if (!validated || !await isCurrent(validated.props, env)) return null;
      return {
        ...validated,
        expiresAt: Math.min(validated.expiresAt, validated.props.expiresAt),
      };
    },
  };
}

// Call from a trusted administrative context only. Never expose this as a public route.
export async function setAccessSubjectStopped({ env, oauth, issuer, subject, stopped }) {
  const state = await subjectStore(env, issuer, subject).setStopped(stopped);
  if (!stopped) return state;
  const userId = await providerUserId(issuer, subject);
  let cursor;
  do {
    const grants = await oauth.listUserGrants(userId, { cursor, limit: 25 });
    for (const grant of grants.items) {
      if (grant.metadata?.generation < state.generation) await oauth.revokeGrant(grant.id, userId);
    }
    cursor = grants.cursor;
  } while (cursor);
  return state;
}
