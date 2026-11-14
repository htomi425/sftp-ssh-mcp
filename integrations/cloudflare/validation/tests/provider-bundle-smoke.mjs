import assert from 'node:assert/strict';
import { build } from 'esbuild';

// Workers' cloudflare: modules are supplied by workerd, not by Node.js.
// Bundle the REAL provider package while preserving Cloudflare runtime imports.
// This checks package exports and module resolution, not Worker execution.
const result = await build({
  entryPoints: [new URL('./provider-import-smoke.mjs', import.meta.url).pathname],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  target: 'es2022',
  external: ['cloudflare:*', 'node:*'],
  write: false,
  logLevel: 'warning',
});
assert.equal(result.errors.length, 0);
assert.ok(result.outputFiles[0].text.includes('OAuthResourceServer'));
console.log('Cloudflare OAuth Provider v1 bundle resolution OK (runtime not executed)');
