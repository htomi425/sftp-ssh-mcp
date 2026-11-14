import { WorkerEntrypoint } from 'cloudflare:workers';

// Test-only Service Binding target. This does NOT issue or validate OAuth
// tokens; it verifies RPC transport, argument integrity and private env access.
export class AuthServer extends WorkerEntrypoint {
  validateToken(resource, token) {
    if (resource !== 'https://resource.example.invalid/mcp' || token !== 'test-token') {
      return { active: false };
    }
    return { active: this.env.TEST_SECRET === 'private-test-value' };
  }
  fetch() {
    return new Response('No public token validation endpoint', { status: 404 });
  }
}
export default { fetch() { return new Response('Not found', { status: 404 }); } };
