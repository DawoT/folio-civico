import { createRemoteJWKSet, jwtVerify } from "jose";

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

    const publicKeys = createRemoteJWKSet(new URL("/cdn-cgi/access/certs", issuer));
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
