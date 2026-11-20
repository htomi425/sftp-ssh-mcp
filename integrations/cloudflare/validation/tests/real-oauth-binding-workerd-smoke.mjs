import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

async function bundle(name) {
  const result = await build({
    entryPoints: [new URL(name, import.meta.url).pathname],
    bundle: true, platform: 'browser', format: 'esm', target: 'es2022',
    external: ['cloudflare:*', 'node:*'], write: false,
  });
  assert.equal(result.errors.length, 0);
  return result.outputFiles[0].text;
}

const mf = new Miniflare({
  workers: [
    {
      name: 'auth', modules: true,
      script: await bundle('./real-oauth-auth-worker.mjs'),
      compatibilityDate: '2026-08-06',
      compatibilityFlags: ['nodejs_compat'],
      kvNamespaces: ['OAUTH_KV'],
    },
    {
      name: 'resource', modules: true,
      script: await bundle('./provider-worker-entry.mjs'),
      compatibilityDate: '2026-08-06',
      compatibilityFlags: ['nodejs_compat'],
      serviceBindings: { AUTH_SERVER: { name: 'auth', entrypoint: 'AuthServer' } },
    },
  ],
});
try {
  const resource = await mf.getWorker('resource');
  const response = await resource.fetch('https://resource.example.invalid/mcp', {
    method: 'POST',
    headers: { Authorization: 'Bearer nonexistent-oauth-token', Accept: 'application/json' },
    body: '{}',
  });
  assert.equal(response.status, 401, 'real provider must reject unissued token via private KV RPC');
  assert.match(response.headers.get('www-authenticate') || '', /Bearer/i);
  console.log('Real OAuthAuthorizationServer and OAuthResourceServer reject unissued token over RPC');
} finally {
  await mf.dispose();
}
