import { readFile } from 'node:fs/promises';
import { validateConnectionOptions } from './connection-config.js';
import { createHostKeyVerifier } from './host-key.js';

export interface Target {
  host: string;
  port?: number;
  user: string;
  password?: string;
  key?: string;
  hostKeySha256: string;
}

export interface TargetRegistry {
  [name: string]: Target;
}

const NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

export function parseTargets(raw: string | undefined, legacy: Target | undefined): TargetRegistry {
  if (!raw) {
    if (!legacy) throw new Error('Missing SSH target configuration');
    return { default: validateTarget(legacy) };
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error('SSH_MCP_TARGETS must be valid JSON'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('SSH_MCP_TARGETS must be an object');
  const entries = Object.entries(parsed);
  if (!entries.length || entries.length > 32) throw new Error('SSH_MCP_TARGETS must define 1 to 32 targets');
  const targets: TargetRegistry = Object.create(null);
  for (const [name, value] of entries) {
    if (!NAME_PATTERN.test(name)) throw new Error('Invalid SSH target name: ' + name);
    targets[name] = validateTarget(value);
  }
  return targets;
}

function validateTarget(value: unknown): Target {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('SSH target must be an object');
  const target = value as Record<string, unknown>;
  if (typeof target.host !== 'string' || typeof target.user !== 'string') throw new Error('SSH target host and user are required');
  const port = target.port === undefined ? 22 : target.port;
  validateConnectionOptions({ host: target.host, username: target.user, port: port as number, readyTimeout: 10000 });
  if (typeof target.hostKeySha256 !== 'string') throw new Error('SSH target hostKeySha256 is required');
  createHostKeyVerifier(target.hostKeySha256);
  if (target.password !== undefined && typeof target.password !== 'string') throw new Error('SSH target password must be a string');
  if (target.key !== undefined && typeof target.key !== 'string') throw new Error('SSH target key must be a path string');
  if (Boolean(target.password) === Boolean(target.key)) throw new Error('SSH target must specify exactly one of password or key');
  return { host: target.host, user: target.user, port: port as number, hostKeySha256: target.hostKeySha256, ...(target.password ? { password: target.password } : { key: target.key as string }) };
}

export function selectTarget(registry: TargetRegistry, name?: string): Target {
  const selected = name ?? (Object.hasOwn(registry, 'default') ? 'default' : Object.keys(registry).length === 1 ? Object.keys(registry)[0] : '');
  if (!selected || !Object.hasOwn(registry, selected)) throw new Error('Unknown or ambiguous SSH target');
  return registry[selected];
}

export async function sshConfigForTarget(target: Target) {
  return {
    host: target.host,
    port: target.port ?? 22,
    username: target.user,
    readyTimeout: 10000,
    hostHash: 'sha256' as const,
    hostVerifier: createHostKeyVerifier(target.hostKeySha256),
    ...(target.password ? { password: target.password } : { privateKey: await readFile(target.key!, 'utf8') }),
  };
}
