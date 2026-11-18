import { createRemoteJWKSet, jwtVerify } from "jose";

// Per-isolate JWKS cache: jose handles key rotation and bounded refresh internally.
// The fetch reference also varies in isolated tests that mock the key endpoint.
let cachedKeySet: {
  issuer: string;
  fetchRef: typeof fetch;
  keys: ReturnType<typeof createRemoteJWKSet>;
} | undefined;

export interface AccessConfig {
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
}

/**
 * Access is a gateway, not a membership database. Verify the signature,
 * issuer and audience before authorizing any per-commission operation.
 */
export async function authenticateAccess(
  request: Request,
  config: AccessConfig
): Promise<string | null> {
  const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!assertion || !config.ACCESS_TEAM_DOMAIN || !config.ACCESS_AUD) return null;

  try {
    const issuer = new URL(config.ACCESS_TEAM_DOMAIN);
    if (issuer.protocol !== "https:" || !issuer.hostname.endsWith(".cloudflareaccess.com")
      || issuer.username || issuer.password || issuer.pathname !== "/") return null;

    const issuerOrigin = issuer.origin;
    const fetchRef = fetch;
    if (!cachedKeySet || cachedKeySet.issuer !== issuerOrigin || cachedKeySet.fetchRef !== fetchRef) {
      cachedKeySet = {
        issuer: issuerOrigin,
        fetchRef,
        keys: createRemoteJWKSet(new URL("/cdn-cgi/access/certs", issuer))
      };
    }
    const publicKeys = cachedKeySet.keys;
    const { payload } = await jwtVerify(assertion, publicKeys, {
      issuer: issuer.origin,
      audience: config.ACCESS_AUD
    });
    return typeof payload.sub === "string" && payload.sub.length > 0 ? payload.sub : null;
  } catch {
    // Do not leak token details or verifier failure modes to callers.
    return null;
  }
}
