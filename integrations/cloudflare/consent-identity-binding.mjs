const encoder = new TextEncoder();
const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), char => char.charCodeAt(0));

/** Authenticated consent identity binding; separate from the provider's browser cookie. */
export function createConsentIdentityBinding(secret) {
  const keyBytes = secret instanceof Uint8Array ? secret :
    typeof secret === 'string' ? encoder.encode(secret) : null;
  if (!keyBytes || keyBytes.length < 32) {
    throw new Error('Consent signing secret must be at least 32 bytes');
  }
  const key = crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return {
    async issue(handle, user) {
      if (typeof handle !== 'string' || !handle || handle.length > 1024) throw new Error('Invalid provider consent handle');
      if (typeof user?.issuer !== 'string' || !user.issuer ||
          typeof user?.id !== 'string' || !user.id) throw new Error('Invalid authenticated identity');
      const payload = encode(encoder.encode(JSON.stringify({
        handle, issuer: user.issuer, subject: user.id, generation: user.generation,
        login: user.login, expires: Date.now() + 600000,
      })));
      const mac = encode(await crypto.subtle.sign('HMAC', await key, encoder.encode(payload)));
      return payload + '.' + mac;
    },
    async verify(token, user) {
      try {
        if (typeof token !== 'string' || token.length > 2048) return null;
        const parts = token.split('.');
        if (parts.length !== 2 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) return null;
        if (parts[0].length > 1800 || parts[1].length !== 43) return null;
        if (encode(decode(parts[0])) !== parts[0] || encode(decode(parts[1])) !== parts[1]) return null;
        if (!await crypto.subtle.verify('HMAC', await key, decode(parts[1]), encoder.encode(parts[0]))) return null;
        const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(parts[0])));
        if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
          Object.keys(payload).length !== 4 + Number(user.generation !== undefined) + Number(user.login !== undefined) ||
          !['handle', 'issuer', 'subject', 'expires'].every(field => Object.hasOwn(payload, field)) ||
          typeof payload.issuer !== 'string' || !payload.issuer ||
          typeof payload.subject !== 'string' || !payload.subject ||
          payload.issuer !== user.issuer || payload.subject !== user.id ||
          payload.generation !== user.generation ||
          payload.login !== user.login ||
          !Number.isSafeInteger(payload.expires) || payload.expires <= Date.now() ||
          payload.expires > Date.now() + 600000 ||
          typeof payload.handle !== 'string' || !payload.handle || payload.handle.length > 1024) return null;
        return payload.handle;
      } catch { return null; }
    },
  };
}
