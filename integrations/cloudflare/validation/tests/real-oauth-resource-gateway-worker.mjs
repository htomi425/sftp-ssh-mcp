import { OAuthResourceServer, insufficientScope } from '@cloudflare/workers-oauth-provider';
import { createResourceWorker } from '../../resource-worker.mjs';

const resource = createResourceWorker({
  OAuthResourceServer, insufficientScope,
  resourceUrl: 'https://resource.example.invalid/mcp',
  authorizationServerUrl: 'https://auth.example.invalid',
});
export default { fetch(request, env, ctx) { return resource.fetch(request, env, ctx); } };
