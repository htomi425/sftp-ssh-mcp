import type { GatewayHttpAuthenticator } from './http-server.js';
import type { GatewayAssertionVerifier } from './gateway-assertion.js';
import type { IdentityTargetPolicy } from './identity-target-policy.js';
import type { ReplayCache } from './gateway-replay.js';
import { createRequestBoundGatewayVerifier } from './gateway-request-binding.js';

/** An origin assertion is NOT an OAuth access token. */
export function createGatewayHttpAuthenticator(
  verifier: GatewayAssertionVerifier,
  replay: ReplayCache,
  identities: IdentityTargetPolicy,
): GatewayHttpAuthenticator {
  const bound = createRequestBoundGatewayVerifier(verifier, replay);
  return {
    verifyRequest(token, request) {
      return identities.resolve(bound.verifyOnce(token, request));
    },
  };
}
