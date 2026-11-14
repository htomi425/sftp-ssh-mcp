import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { createGatewayAssertionVerifier } from '../build/gateway-assertion.js';
import { createInMemoryReplayCache } from '../build/gateway-replay.js';
import { parseIdentityTargetPolicy } from '../build/identity-target-policy.js';
import { createGatewayHttpAuthenticator } from '../build/gateway-http-auth.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';

const keys = generateKeyPairSync('ed25519');
const issuer = 'https://gateway.example';
const audience = 'ssh-mcp-origin';
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
let nonce = 0;
function signed(body, overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: issuer, sub: 'alice', aud: audience, iat: now - 1, nbf: now - 1,
    exp: now + 30, jti: 'gateway_nonce_' + String(++nonce).padStart(16, '0'),
    htm: 'POST', htu: '/mcp', body_sha256: createHash('sha256').update(body).digest('base64url'),
    ...overrides,
  };
  const input = encode({ alg: 'EdDSA', typ: 'JWT' }) + '.' + encode(claims);
  return input + '.' + sign(null, Buffer.from(input), keys.privateKey).toString('base64url');
}
const body = JSON.stringify({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'gateway-test', version: '1' } },
});

test('gateway HTTP authenticates a signed raw request once before MCP execution', async () => {
  const verifier = createGatewayAssertionVerifier({
    issuer, audience, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }),
  });
  const policy = parseIdentityTargetPolicy(JSON.stringify([{ issuer, subject: 'alice', targets: ['alpha'] }]), new Set(['alpha']));
  const auth = createGatewayHttpAuthenticator(verifier, createInMemoryReplayCache(), policy);
  let constructed = 0;
  const handler = createStreamableHttpHandler(principal => {
    constructed++;
    assert.equal(principal.targets.has('alpha'), true);
    return new McpServer({ name: 'gateway-test', version: '1.0.0' });
  });
  const server = createAuthenticatedHttpServer(auth, handler);
  const { port } = await listenLoopback(server, '127.0.0.1', 0);
  const url = `http://127.0.0.1:${port}/mcp`;
  async function send(token, payload = body) {
    return fetch(url, { method: 'POST', headers: {
      authorization: 'Bearer ' + token,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    }, body: payload });
  }
  try {
    const token = signed(body);
    const valid = await send(token);
    assert.equal(valid.status, 200);
    assert.match(await valid.text(), /gateway-test/);
    assert.equal((await send(token)).status, 401);
    assert.equal((await send(signed(body), body + ' ')).status, 401);
    assert.equal((await send(signed(body, { sub: 'bob' }))).status, 401);
    assert.equal((await send(signed(body, { htm: 'GET' }))).status, 401);
    assert.equal(constructed, 1);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
