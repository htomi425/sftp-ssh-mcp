import { OAuthAuthorizationServer } from '@cloudflare/workers-oauth-provider';
import { WorkerEntrypoint } from 'cloudflare:workers';

const authorizationServer = new OAuthAuthorizationServer({
  issuer: 'https://auth.example.invalid',
  resources: ['https://resource.example.invalid/mcp'],
  scopesSupported: ['mcp:invoke'],
  clientIdMetadataDocumentEnabled: false,
});

export class AuthServer extends WorkerEntrypoint {
  fetch(request) {
    return authorizationServer.fetch(request, this.env, this.ctx);
  }
  validateToken(resource, token) {
    return authorizationServer.validateToken(resource, token, this.env);
  }
}

export default {
  fetch(request, env, ctx) {
    return authorizationServer.fetch(request, env, ctx);
  },
};
