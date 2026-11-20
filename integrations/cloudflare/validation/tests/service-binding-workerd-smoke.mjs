import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

async function bundle(name) {
  const result = await build({
    entryPoints: [new URL(name, import.meta.url).pathname],
    bundle: true, platform: 'browser', format: 'esm', target: 'es2022',
    external: ['cloudflare:*', 'node:*'], write: false,
  });
  return result.outputFiles[0].text;
}

const mf = new Miniflare({
  workers: [
    {
      name: 'auth',
      modules: true,
      script: await bundle('./service-binding-auth-worker.mjs'),
      compatibilityDate: '2026-08-06',
      compatibilityFlags: ['nodejs_compat'],
      bindings: { TEST_SECRET: 'private-test-value' },
    },
    {
      name: 'resource',
      modules: true,
      script: await bundle('./service-binding-resource-worker.mjs'),
      compatibilityDate: '2026-08-06',
      compatibilityFlags: ['nodejs_compat'],
      serviceBindings: { AUTH_SERVER: { name: 'auth', entrypoint: 'AuthServer' } },
    },
  ],
});
try {
  const worker = await mf.getWorker('resource');
  const valid = await worker.fetch('https://resource.example.invalid/test', {
    headers: { Authorization: 'Bearer test-token' },
  });
  assert.equal(valid.status, 200);
  assert.deepEqual(await valid.json(), { active: true });

  const invalid = await worker.fetch('https://resource.example.invalid/test', {
    headers: { Authorization: 'Bearer invalid' },
  });
  assert.equal(invalid.status, 200);
  assert.deepEqual(await invalid.json(), { active: false });
  console.log('workerd Service Binding RPC and private env verified');
} finally {
  await mf.dispose();
}
