import { timingSafeEqual } from 'node:crypto';

const SHA256_HEX = /^[a-f0-9]{64}$/i;

export function normalizeHostKeySha256(value: string): string {
  const normalized = value.trim().replace(/^SHA256:/i, '');
  if (!SHA256_HEX.test(normalized)) {
    throw new Error('SSH host key fingerprint must be a 64-character SHA-256 hex digest');
  }
  return normalized.toLowerCase();
}

export function createHostKeyVerifier(expectedFingerprint: string): (fingerprint: string) => boolean {
  const expected = Buffer.from(normalizeHostKeySha256(expectedFingerprint), 'hex');
  return (fingerprint: string): boolean => {
    if (!SHA256_HEX.test(fingerprint)) return false;
    const actual = Buffer.from(fingerprint, 'hex');
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  };
}
