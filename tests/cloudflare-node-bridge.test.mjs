import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { createAuthenticatedHttpServer, listenLoopback } from '../build/http-server.js';
import { createStreamableHttpHandler } from '../build/http-mcp.js';
import { createGatewayAssertionVerifier } from '../build/gateway-assertion.js';
import { createInMemoryReplayCache } from '../build/gateway-replay.js';
import { parseIdentityTargetPolicy } from '../build/identity-target-policy.js';
import { createGatewayHttpAuthenticator } from '../build/gateway-http-auth.js';
import { createToolServer } from '../build/tool-server.js';
import { forwardVerifiedIdentity } from '../integrations/cloudflare/resource-gateway.mjs';

const keys = generateKeyPairSync('ed25519');
const issuer = 'https://gateway.example.invalid';
const audience = 'ssh-mcp-origin';
const upstreamIssuer = 'https://idp.example.invalid';
const identity = { issuer: upstreamIssuer, subject: 'alice', scopes: ['mcp:invoke'] };
const resource = 'https://resource.example.invalid/mcp';
const targets = {
  alpha: { host: '127.0.0.1', user: 'tester', password: 'unused', hostKeySha256: 'a'.repeat(64) },
  beta: { host: '127.0.0.2', user: 'tester', password: 'unused', hostKeySha256: 'b'.repeat(64) },
};

test('Cloudflare-signed request reaches Node MCP and preserves per-identity target authorization', async () => {
  const verifier = createGatewayAssertionVerifier({
    issuer, audience, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }),
  });
  const identities = parseIdentityTargetPolicy(JSON.stringify([
    { issuer, subject: JSON.stringify([upstreamIssuer, 'alice']), targets: ['alpha'] },
  ]), new Set(Object.keys(targets)));
  const auth = createGatewayHttpAuthenticator(verifier, createInMemoryReplayCache(), identities);
  const server = createAuthenticatedHttpServer(auth,
    createStreamableHttpHandler(principal => createToolServer(targets, { principal }, 'http')));
  const { port } = await listenLoopback(server, '127.0.0.1', 0);
  const local = 'http://127.0.0.1:' + port + '/mcp';
  const forwarded = [];
  const env = {
    GATEWAY_PRIVATE_KEY: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    GATEWAY_ISSUER: issuer, GATEWAY_AUDIENCE: audience,
    ORIGIN: { async fetch(request) {
      forwarded.push(request.clone());
      return fetch(local, {
        method: request.method, headers: request.headers,
        body: request.method === 'POST' ? await request.arrayBuffer() : undefined,
      });
    } },
  };
  let id = 0;
  async function rpc(method, params, who = identity) {
    const request = new Request(resource, {
      method: 'POST',
      headers: { authorization: 'Bearer fake-client-oauth-token',
        'content-type': 'application/json', accept: 'application/json, text/event-stream',
        'x-user': 'admin', 'x-targets': 'beta' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
    });
    const response = await forwardVerifiedIdentity(request, env, who, {
      resource, requiredScope: 'mcp:invoke',
    });
    if (response.status !== 200) return { status: response.status };
    const text = await response.text();
    const data = text.startsWith('event:')
      ? text.split('\n').find(line => line.startsWith('data: '))?.slice(6) : text;
    return { status: response.status, message: JSON.parse(data) };
  }
  try {
    const initialized = await rpc('initialize', {
      protocolVersion: '2025-06-18', capabilities: {},
      clientInfo: { name: 'worker-node-bridge-test', version: '1' },
    });
    assert.equal(initialized.status, 200);
    assert.equal(initialized.message.result.serverInfo.name, 'SSH MCP Server');
    for (const [name, args] of [
      ['exec', { target: 'beta', command: 'echo forbidden' }],
      ['sftp_list', { target: 'beta', remotePath: '/tmp' }],
      ['sftp_upload', { target: 'beta', localPath: '/etc/passwd', remotePath: '/tmp/blocked' }],
      ['sftp_download', { target: 'beta', remotePath: '/tmp/blocked', localPath: '/tmp/blocked' }],
    ]) {
      const result = await rpc('tools/call', { name, arguments: args });
      assert.equal(result.status, 200, name);
      assert.match(JSON.stringify(result.message), /access denied/i, name);
    }
    assert.equal(forwarded.length, 5);
    for (const request of forwarded) {
      assert.equal(request.headers.has('x-user'), false);
      assert.equal(request.headers.has('x-targets'), false);
      assert.match(request.headers.get('authorization'), /^Bearer [^.]+\.[^.]+\.[^.]+$/);
    }
    const unknown = await rpc('tools/list', {}, { ...identity, subject: 'mallory' });
    assert.equal(unknown.status, 401, 'unmapped upstream identity must be rejected at Node');
    const scope = await rpc('tools/list', {}, { ...identity, scopes: [] });
    assert.equal(scope.status, 403, 'missing OAuth scope must be rejected at gateway');
    assert.equal(forwarded.length, 6, 'scope failure must not reach origin');
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
