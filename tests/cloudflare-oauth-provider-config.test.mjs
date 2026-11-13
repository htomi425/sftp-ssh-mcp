import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createOAuthProviderConfiguration } from '../integrations/cloudflare/oauth-provider-config.mjs';

const authorizationHandler = { fetch() { return new Response('login required', { status: 401 }); } };
const resourceHandler = { fetch() { return new Response('unauthorized', { status: 401 }); } };
const valid = {
  authorizationHandler, resourceHandler,
  resourceUrl: 'https://ssh-mcp.example/mcp',
  authorizationServerUrl: 'https://ssh-mcp.example',
};
test('OAuth provider metadata is resource-bound with distinct protected and authorization handlers', () => {
  const options = createOAuthProviderConfiguration(valid);
  assert.equal(options.apiRoute, '/mcp');
  assert.equal(options.apiHandler, resourceHandler);
  assert.equal(options.defaultHandler, authorizationHandler);
  assert.equal(options.resourceMetadata.resource, valid.resourceUrl);
  assert.deepEqual(options.resourceMetadata.authorization_servers, ['https://ssh-mcp.example']);
  assert.deepEqual(options.resourceMetadata.scopes_supported, ['mcp:invoke']);
  assert.equal(options.clientIdMetadataDocumentEnabled, true);
  assert.equal(options.tokenEndpoint, '/oauth/token');
});
test('OAuth provider setup fails closed without explicit authentication and consent handler', () => {
  assert.throws(() => createOAuthProviderConfiguration({ ...valid, authorizationHandler: undefined }), /authorization\/consent/);
  assert.throws(() => createOAuthProviderConfiguration({ ...valid, resourceHandler: undefined }), /resource handler/);
});
test('OAuth provider rejects unsafe or mismatched resource identifiers', () => {
  for (const resourceUrl of [
    'http://ssh-mcp.example/mcp', 'https://evil@example.com/mcp',
    'https://ssh-mcp.example/other', 'https://ssh-mcp.example/mcp?admin=true',
  ]) assert.throws(() => createOAuthProviderConfiguration({ ...valid, resourceUrl }));
  assert.throws(() => createOAuthProviderConfiguration({ ...valid, authorizationServerUrl: 'http://ssh-mcp.example' }), /HTTPS/);
});
