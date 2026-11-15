const encoder = new TextEncoder();
const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), char => char.charCodeAt(0));

/** Authenticated consent identity binding; separate from the provider's browser cookie. */
export function createConsentIdentityBinding(secret) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('Consent signing secret must be at least 32 characters');
  const key = crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return {
    async issue(handle, user) {
      const payload = encode(encoder.encode(JSON.stringify({
        handle, issuer: user.issuer, subject: user.id, expires: Date.now() + 600000,
      })));
      const mac = encode(await crypto.subtle.sign('HMAC', await key, encoder.encode(payload)));
      return payload + '.' + mac;
    },
    async verify(token, user) {
      try {
        const parts = token.split('.');
        if (parts.length !== 2 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) return null;
        if (!await crypto.subtle.verify('HMAC', await key, decode(parts[1]), encoder.encode(parts[0]))) return null;
        const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(parts[0])));
        if (payload.issuer !== user.issuer || payload.subject !== user.id ||
          !Number.isSafeInteger(payload.expires) || payload.expires <= Date.now() ||
          payload.expires > Date.now() + 600000 ||
          typeof payload.handle !== 'string' || !payload.handle) return null;
        return payload.handle;
      } catch { return null; }
    },
  };
}
