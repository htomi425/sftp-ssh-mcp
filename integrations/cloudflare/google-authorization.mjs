import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createIdentityAuthorizationWorker } from './consent-authorization-worker.mjs';

const googleIssuer = 'https://accounts.google.com';
const callbackPath = '/google/callback';
const consentPath = '/google/consent';
const cookieName = '__Host-ssh_mcp_google';
const lifetime = 600;
const randomPattern = /^[a-f0-9]{64}$/;
const epoch = () => Math.floor(Date.now() / 1000);
const random = () => Array.from(crypto.getRandomValues(new Uint8Array(32)),
  byte => byte.toString(16).padStart(2, '0')).join('');
const googleKeys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'), { timeoutDuration: 5000 });

function reply(status, message, headers) {
  const response = new Response(message, { status, headers });
  response.headers.set('Cache-Control', 'no-store');
  response.headers.set('Referrer-Policy', 'no-referrer');
  return response;
}

function browserTransaction(request) {
  const cookie = request.headers.get('Cookie') ?? '';
  if (cookie.length > 8192) return null;
  const matches = cookie.split(';').map(part => part.trim()).filter(part => part.startsWith(cookieName + '='));
  if (matches.length !== 1) return null;
  const parts = matches[0].slice(cookieName.length + 1).split('.');
  if (parts.length !== 2 || !parts.every(part => randomPattern.test(part))) return null;
  const [state, proof] = parts;
  return { state, proof };
}

function browserCookie(value, ttl) {
  return cookieName + '=' + value + '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=' + ttl;
}

function flow(env, state) {
  return env.OAUTH_GOOGLE_FLOW.getByName(state);
}

export function createGoogleAuthorizationFlow(DurableObject) {
  return class GoogleAuthorizationFlow extends DurableObject {
    async begin(pending) {
      await this.ctx.storage.put('pending', pending);
      await this.ctx.storage.setAlarm(pending.deadline * 1000);
    }

    async take(proof) {
      return this.ctx.storage.transaction(async storage => {
        const pending = await storage.get('pending');
        if (!pending || pending.proof !== proof || pending.deadline <= epoch()) return null;
        await storage.delete('pending');
        return pending;
      });
    }

    async saveIdentity(session) {
      return this.ctx.storage.transaction(async storage => {
        if (session.deadline <= epoch()) return false;
        await storage.put('session', session);
        return true;
      });
    }

    async readSession(proof) {
      const session = await this.ctx.storage.get('session');
      return session && session.proof === proof && session.deadline > epoch()
        ? { query: session.query, user: session.user } : null;
    }

    async alarm() {
      await this.ctx.storage.deleteAll();
    }
  };
}

export function createGoogleAuthorizationWorker({
  OAuthAuthorizationServer, OAuthError, providerOptions, secretBinding, exchange,
}) {
  const browserAuthorization = createGoogleBrowserAuthorization({ origin: providerOptions.issuer, exchange });
  return createIdentityAuthorizationWorker({
    OAuthAuthorizationServer, OAuthError, providerOptions, secretBinding, browserAuthorization,
    issuer: googleIssuer, authenticateUser: browserAuthorization.authenticateUser,
  });
}

function createGoogleBrowserAuthorization({ origin, exchange = fetch }) {
  if (!URL.canParse(origin) || new URL(origin).origin !== origin || !origin.startsWith('https://')) {
    throw new Error('Google OAuth requires a canonical HTTPS authorization origin');
  }
  const redirectUri = origin + callbackPath;

  return {
    async authenticateUser(request, env) {
      const transaction = browserTransaction(request);
      if (!transaction) return null;
      const session = await flow(env, transaction.state).readSession(transaction.proof);
      return session?.user ?? null;
    },

    async fetch(request, env, ctx, worker, parseAuthRequest) {
      const url = new URL(request.url);
      if (!['/authorize', callbackPath, consentPath].includes(url.pathname)) return worker.fetch(request, env, ctx);
      if (url.origin !== origin) return reply(404, 'Not found');
      if (url.pathname === '/authorize' && request.method !== 'GET') return worker.fetch(request, env, ctx);
      if (request.method !== 'GET') return reply(404, 'Not found');

      const allowedEmails = (env.GOOGLE_ALLOWED_EMAILS ?? '').split(',').map(email => email.trim().toLowerCase()).filter(Boolean);
      if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !allowedEmails.length) {
        return reply(503, 'Authorization service unavailable');
      }

      if (url.pathname === '/authorize') {
        if (url.search.length > 8192) return reply(414, 'Authorization request URI too long');
        if (request.headers.has('Origin') && request.headers.get('Origin') !== origin) {
          return reply(403, 'Forbidden');
        }
        const state = random();
        const proof = random();
        const nonce = random();
        const verifier = random();
        try {
          await parseAuthRequest(request, env);
          await flow(env, state).begin({ proof, nonce, verifier, query: url.search, deadline: epoch() + lifetime });
        } catch (error) {
          if (error?.name === 'AuthorizationError') return reply(400, 'Invalid authorization request');
          return reply(503, 'Authorization service unavailable');
        }
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
        const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
          .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const google = new URL('/o/oauth2/v2/auth', googleIssuer);
        google.search = new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID, redirect_uri: redirectUri, response_type: 'code',
          scope: 'openid email', prompt: 'select_account', state, nonce,
          code_challenge: challenge, code_challenge_method: 'S256',
        });
        return reply(302, null, {
          Location: google.href, 'Set-Cookie': browserCookie(state + '.' + proof, lifetime),
        });
      }

      const transaction = browserTransaction(request);
      if (!transaction || url.searchParams.getAll('state').length !== 1 ||
          url.searchParams.get('state') !== transaction.state) {
        return reply(400, 'Invalid Google authorization response. Start authorization again.');
      }

      const code = url.searchParams.get('code');
      try {
        const state = flow(env, transaction.state);
        if (url.pathname === consentPath) {
          const session = await state.readSession(transaction.proof);
          if (!session) return reply(400, 'This Google authorization is no longer valid. Start authorization again.');
          const authorize = new Request(origin + '/authorize' + session.query, { headers: request.headers });
          return worker.fetch(authorize, env, ctx);
        }
        const pending = await state.take(transaction.proof);
        if (!pending) return reply(400, 'This Google authorization is no longer valid. Start authorization again.');
        if (url.searchParams.getAll('code').length !== 1 || !code || code.length > 2048 ||
            url.searchParams.has('error')) {
          return reply(400, 'Google authorization was not completed. Start authorization again.');
        }
        const result = await exchange('https://oauth2.googleapis.com/token', {
          method: 'POST',
          body: new URLSearchParams({
            grant_type: 'authorization_code', client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: redirectUri, code, code_verifier: pending.verifier,
          }),
          redirect: 'manual',
          signal: AbortSignal.timeout(5000),
        });
        if (!result.ok) return reply(502, 'Google token exchange failed');
        const { id_token: token } = await result.json();
        const { payload } = await jwtVerify(token, googleKeys, {
          issuer: [googleIssuer, 'accounts.google.com'], audience: env.GOOGLE_CLIENT_ID,
          algorithms: ['RS256'], requiredClaims: ['sub', 'iat', 'exp', 'nonce'], maxTokenAge: '10 minutes',
        });
        const email = typeof payload.email === 'string' ? payload.email.toLowerCase() : '';
        const domain = /^[^@\s]+@([^@\s]+)$/.exec(email)?.[1];
        // Google is authoritative for Gmail and verified Workspace identities.
        const authoritative = domain === 'gmail.com' || (domain && payload.hd === domain);
        if (payload.nonce !== pending.nonce || payload.email_verified !== true || !authoritative ||
            !allowedEmails.includes(email) || typeof payload.sub !== 'string' || !payload.sub ||
            payload.sub.length > 255 || !Number.isSafeInteger(payload.exp) || payload.exp <= epoch() ||
            (payload.azp !== undefined && payload.azp !== env.GOOGLE_CLIENT_ID) ||
            pending.deadline <= epoch()) {
          return reply(403, 'Google account not authorized');
        }
        const user = {
          issuer: googleIssuer, id: payload.sub, expiresAt: payload.exp, login: transaction.state,
        };
        const saved = await state.saveIdentity({
          proof: transaction.proof, deadline: pending.deadline, query: pending.query, user,
        });
        if (!saved) return reply(400, 'This Google authorization is no longer valid. Start authorization again.');
        return reply(303, null, { Location: consentPath + '?state=' + transaction.state });
      } catch {
        return reply(503, 'Authorization service unavailable');
      }
    },
  };
}
