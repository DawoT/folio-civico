import { describe, expect, it, vi, afterEach } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { handleApiRequest } from "./index";
import { makeD1 } from "../../../tests/helpers/d1";

const issuer = "https://folio-test.cloudflareaccess.com";
const audience = "folio-civico-preview-audience";

afterEach(() => vi.unstubAllGlobals());

async function tokenFor(subject: string, overrides: {aud?:string; iss?:string; expired?:boolean} = {}) {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "test-key";
  const fetcher = vi.fn(async () => Response.json({ keys: [jwk] }));
  vi.stubGlobal("fetch", fetcher);
  const token = await new SignJWT({ purpose: "access" })
    .setProtectedHeader({ alg:"RS256", kid:"test-key" })
    .setIssuer(overrides.iss ?? issuer)
    .setAudience(overrides.aud ?? audience)
    .setSubject(subject)
    .setIssuedAt(overrides.expired ? Math.floor(Date.now()/1000)-3600 : Math.floor(Date.now()/1000))
    .setExpirationTime(overrides.expired ? Math.floor(Date.now()/1000)-1800 : Math.floor(Date.now()/1000)+300)
    .sign(privateKey);
  return { token, fetcher };
}

describe("signed Access identity to tenant-aware API", () => {
  function fixture() {
    const f = makeD1();
    f.sqlite.exec(`
      INSERT INTO commissions(id,name) VALUES ('c_a','Comisión A'),('c_b','Comisión B');
      INSERT INTO commission_members(commission_id,subject,role,active)
        VALUES ('c_a','alice','member',1),('c_b','bob','member',1);
    `);
    return f;
  }
  async function call(db:D1Database, token:string, path="/api/commissions") {
    return handleApiRequest(new Request("https://folio.test"+path, {
      headers: { "Cf-Access-Jwt-Assertion":token }
    }), {DB:db, ACCESS_TEAM_DOMAIN:issuer, ACCESS_AUD:audience});
  }

  it("accepts a signed token and returns only the authenticated member's commission", async () => {
    const f=fixture();
    try {
      const {token,fetcher}=await tokenFor("alice");
      const response=await call(f.db, token);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject([{id:"c_a"}]);
      expect(fetcher).toHaveBeenCalled();
    } finally {f.close();}
  });

  it("reuses cached Access signing keys between requests", async () => {
    const f=fixture();
    try {
      const {token,fetcher}=await tokenFor("alice");
      const first=await call(f.db,token);
      const second=await call(f.db,token);
      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      expect(fetcher).toHaveBeenCalledTimes(1);
    } finally {f.close();}
  });

  it("rejects a valid signature with wrong audience", async () => {
    const f=fixture();
    try {
      const {token}=await tokenFor("alice",{aud:"other-app"});
      expect((await call(f.db,token)).status).toBe(401);
    } finally {f.close();}
  });

  it("rejects a valid signature with wrong issuer", async () => {
    const f=fixture();
    try {
      const {token}=await tokenFor("alice",{iss:"https://other.cloudflareaccess.com"});
      expect((await call(f.db,token)).status).toBe(401);
    } finally {f.close();}
  });

  it("rejects expired signed tokens", async () => {
    const f=fixture();
    try {
      const {token}=await tokenFor("alice",{expired:true});
      expect((await call(f.db,token)).status).toBe(401);
    } finally {f.close();}
  });
});
