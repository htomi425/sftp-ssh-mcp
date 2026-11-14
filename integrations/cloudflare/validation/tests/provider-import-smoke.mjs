import assert from 'node:assert/strict';
import { OAuthAuthorizationServer, OAuthResourceServer, insufficientScope } from '@cloudflare/workers-oauth-provider';
import { createResourceWorker } from '../../resource-worker.mjs';

// Smoke-check the REAL installed package's exported v1 API. No credentials,
// KV writes, network requests, or production deployment.
assert.equal(typeof OAuthAuthorizationServer, 'function');
assert.equal(typeof OAuthResourceServer, 'function');
assert.equal(typeof insufficientScope, 'function');

const instance = createResourceWorker({
  OAuthResourceServer,
  insufficientScope,
  resourceUrl: 'https://example.invalid/mcp',
  authorizationServerUrl: 'https://auth.example.invalid',
});
assert.ok(instance);
console.log('Workers OAuth Provider v1 import and resource-server construction OK');
