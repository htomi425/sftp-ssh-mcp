import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';
import { createGatewayAssertionVerifier } from '../build/gateway-assertion.js';
import { createInMemoryReplayCache } from '../build/gateway-replay.js';
import { parseIdentityTargetPolicy } from '../build/identity-target-policy.js';
import { createGatewayHttpAuthenticator } from '../build/gateway-http-auth.js';
import { createToolServer } from '../build/tool-server.js';

const keys = generateKeyPairSync('ed25519');
const issuer = 'https://gateway.example.invalid';
const audience = 'ssh-mcp-origin';
const targets = {
  alpha: { host: '127.0.0.1', user: 'tester', password: 'unused', hostKeySha256: 'a'.repeat(64) },
  beta: { host: '127.0.0.2', user: 'tester', password: 'unused', hostKeySha256: 'b'.repeat(64) },
};
const b64 = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
let nonce = 0;
function assertion(body, subject, overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: issuer, sub: subject, aud: audience, iat: now - 1, nbf: now - 1,
    exp: now + 30, jti: 'identity_target_nonce_' + String(++nonce).padStart(16, '0'),
    htm: 'POST', htu: '/mcp',
    body_sha256: createHash('sha256').update(body).digest('base64url'),
    ...overrides,
  };
  const signed = b64({ alg: 'EdDSA', typ: 'JWT' }) + '.' + b64(claims);
  return signed + '.' + sign(null, Buffer.from(signed), keys.privateKey).toString('base64url');
}

test('signed gateway identities enforce per-user SSH target permissions through real HTTP MCP tools', async () => {
  const verifier = createGatewayAssertionVerifier({
    issuer, audience, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }),
  });
  const identities = parseIdentityTargetPolicy(JSON.stringify([
    { issuer, subject: 'alice', targets: ['alpha'] },
    { issuer, subject: 'bob', targets: ['beta'] },
  ]), new Set(Object.keys(targets)));
  const authenticator = createGatewayHttpAuthenticator(verifier, createInMemoryReplayCache(), identities);
  const server = createAuthenticatedHttpServer(authenticator,
    createStreamableHttpHandler(principal => createToolServer(targets, { principal }, 'http')));
  const { port } = await listenLoopback(server, '127.0.0.1', 0);
  let id = 0;
  async function rpc(subject, method, params, options = {}) {
    const body = JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params });
    const token = options.token ?? assertion(body, subject, options.claims);
    const response = await fetch('http://127.0.0.1:' + port + '/mcp', {
      method: 'POST', headers: {
        authorization: 'Bearer ' + token,
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
      }, body,
    });
    if (response.status !== 200) return { status: response.status };
    const text = await response.text();
    const data = text.startsWith('event:')
      ? text.split('\n').find(line => line.startsWith('data: '))?.slice(6) : text;
    return { status: response.status, message: JSON.parse(data) };
  }
  try {
    for (const subject of ['alice', 'bob']) {
      const init = await rpc(subject, 'initialize', {
        protocolVersion: '2025-06-18', capabilities: {},
        clientInfo: { name: 'gateway-authz-test', version: '1' },
      });
      assert.equal(init.status, 200);
    }
    for (const [subject, forbidden] of [['alice', 'beta'], ['bob', 'alpha']]) {
      for (const [name, args] of [
        ['exec', { target: forbidden, command: 'echo should-not-execute' }],
        ['sftp_list', { target: forbidden, remotePath: '/tmp' }],
        ['sftp_upload', { target: forbidden, localPath: '/etc/passwd', remotePath: '/tmp/blocked' }],
        ['sftp_download', { target: forbidden, remotePath: '/etc/passwd', localPath: '/tmp/blocked' }],
      ]) {
        const result = await rpc(subject, 'tools/call', { name, arguments: args });
        assert.equal(result.status, 200, subject + ':' + name);
        assert.match(JSON.stringify(result.message), /access denied/i, subject + ':' + name);
      }
    }
    const unknown = await rpc('mallory', 'tools/list', {});
    assert.equal(unknown.status, 401, 'unmapped signed identity rejected');
    const tampered = await rpc('alice', 'tools/list', {}, { claims: { body_sha256: 'A'.repeat(43) } });
    assert.equal(tampered.status, 401, 'signed but incorrectly bound body rejected');
    const noTarget = await rpc('alice', 'tools/call', { name: 'exec', arguments: { command: 'echo no-default' } });
    assert.equal(noTarget.status, 200);
    assert.match(JSON.stringify(noTarget.message), /access denied|target.*required|specify.*target/i);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
