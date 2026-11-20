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
      script: await bundle('./service-binding-auth-worker.mjs'),
      compatibilityDate: '2026-08-06',
      compatibilityFlags: ['nodejs_compat'],
      bindings: { TEST_SECRET: 'private-test-value' },
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
    headers: { Authorization: 'Bearer invalid', Accept: 'application/json' },
    body: '{}',
  });
  assert.equal(response.status, 401, 'real OAuthResourceServer must reject invalid token via RPC');
  assert.match(response.headers.get('www-authenticate') || '', /Bearer/i);
  console.log('OAuthResourceServer rejected invalid token via workerd Service Binding');
} finally {
  await mf.dispose();
}
