import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

const bundle = await build({
  entryPoints: [new URL('./provider-worker-entry.mjs', import.meta.url).pathname],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  target: 'es2022',
  external: ['cloudflare:*', 'node:*'],
  write: false,
});
assert.equal(bundle.errors.length, 0);
const mf = new Miniflare({
  modules: true,
  script: bundle.outputFiles[0].text,
  // Use the date supported by the installed workerd binary in CI.
  compatibilityDate: '2026-08-06',
  compatibilityFlags: ['nodejs_compat'],
});
try {
  const response = await mf.dispatchFetch('https://resource.example.invalid/mcp', {
    method: 'POST',
    headers: { Accept: 'application/json' },
    body: '{}',
  });
  assert.equal(response.status, 401, 'missing bearer token must be rejected');
  const challenge = response.headers.get('www-authenticate') || '';
  assert.match(challenge.toLowerCase(), /bearer/);
  console.log('Real workerd OAuth resource server rejects unauthenticated MCP request');
} finally {
  await mf.dispose();
}
