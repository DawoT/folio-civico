import { afterEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleApiRequest, type ApiEnv } from "./index";

const url = "https://folio.test/api/readiness/core";
const issuer = "https://readiness-local.cloudflareaccess.com";
const audience = "folio-core-readiness-test";

afterEach(() => vi.unstubAllGlobals());

async function signedFixture() {
  const f = makeD1();
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "core-readiness-jwk";
  vi.stubGlobal("fetch", vi.fn(async () => Response.json({ keys: [jwk] })));
  const token = async (sub: string) => new SignJWT({})
    .setProtectedHeader({ alg:"RS256", kid:jwk.kid })
    .setIssuer(issuer).setAudience(audience).setSubject(sub)
    .setIssuedAt().setExpirationTime("10m").sign(privateKey);
  const env: ApiEnv = {
    DB: f.db, ACCESS_TEAM_DOMAIN: issuer, ACCESS_AUD: audience,
    COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT: "operator"
  };
  const request = (jwt:string,method="GET") => new Request(url,{
    method, headers:{ "Cf-Access-Jwt-Assertion":jwt }
  });
  return { ...f, env, token, request };
}

describe("authenticated API-core readiness contract", () => {
  it("keeps the existing public liveness signal but never treats it as readiness",async()=>{
    const liveness = await handleApiRequest(new Request("https://folio.test/health"),{});
    expect(liveness.status).toBe(200);
    expect(await liveness.json()).toEqual({status:"ok"});
    const readiness=await handleApiRequest(new Request(url),{});
    expect(readiness.status).toBe(401);
    expect(readiness.headers.get("Cache-Control")).toBe("no-store");
    expect(JSON.stringify(await readiness.json())).not.toContain("ready");
  });

  it("denies forged identity headers and never exposes dependency details to anonymous clients",async()=>{
    const req=new Request(url,{headers:{
      "Cf-Access-Authenticated-User-Email":"operator@example.test"
    }});
    const response=await handleApiRequest(req,{});
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({error:"Unauthorized"});
  });

  it("limits readiness to the explicitly configured operator identity",async()=>{
    const f=await signedFixture();
    try{
      const other=await f.token("member");
      const forbidden=await handleApiRequest(f.request(other),f.env);
      expect(forbidden.status).toBe(403);
      expect(await forbidden.json()).toEqual({error:"Forbidden"});
      const configuredOperator=await f.token("operator");
      const disabled=await handleApiRequest(f.request(configuredOperator),{
        ...f.env,COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT:undefined,DB:undefined
      });
      expect(disabled.status).toBe(403);
      expect(await disabled.json()).toEqual({error:"Forbidden"});
      const invalidMethod=await handleApiRequest(f.request(configuredOperator,"POST"),f.env);
      expect(invalidMethod.status).toBe(405);
      expect(invalidMethod.headers.get("Cache-Control")).toBe("no-store");
    }finally{f.close();}
  });

  it("returns a narrowly scoped ready only when D1 and required schema are available",async()=>{
    const f=await signedFixture();
    try{
      const operator=await f.token("operator");
      const valid=await handleApiRequest(f.request(operator),f.env);
      expect(valid.status).toBe(200);
      expect(valid.headers.get("Cache-Control")).toBe("no-store");
      expect(await valid.json()).toEqual({status:"ready",scope:"api-core"});

      const unavailable=await handleApiRequest(f.request(operator),{...f.env,DB:undefined});
      expect(unavailable.status).toBe(503);
      expect(await unavailable.json()).toEqual({error:"Service unavailable"});

      f.sqlite.exec("DROP TABLE audit_events");
      const missingSchema=await handleApiRequest(f.request(operator),f.env);
      expect(missingSchema.status).toBe(503);
      expect(await missingSchema.json()).toEqual({error:"Service unavailable"});
    }finally{f.close();}
  });

  it("does not expose a second readiness endpoint from archived prototypes", async () => {
    const f = await signedFixture();
    try {
      const operator = await f.token("operator");
      const duplicate = await handleApiRequest(
        new Request("https://folio.test/api/internal/readiness", {
          headers: { "Cf-Access-Jwt-Assertion": operator }
        }), f.env
      );
      expect(duplicate.status).toBe(404);
      expect(await duplicate.json()).toEqual({ error: "Not found" });
    } finally {
      f.close();
    }
  });

  // The manual pilot cannot be ready when its review/checklist tables
  // are absent, even if the audit and admission guards are still present.
  it.each(["checklist_items", "observations"] as const)(
    "fails closed when the manual-flow table %s is absent", async (table) => {
      const f = await signedFixture();
      try {
        const operator = await f.token("operator");
        expect((await handleApiRequest(f.request(operator), f.env)).status).toBe(200);
        // Identifiers come from this fixed test list, never request parameters.
        f.sqlite.exec(`DROP TABLE "${table}"`);
        const missing = await handleApiRequest(f.request(operator), f.env);
        expect(missing.status).toBe(503);
        expect(missing.headers.get("Cache-Control")).toBe("no-store");
        expect(await missing.json()).toEqual({ error: "Service unavailable" });
      } finally {
        f.close();
      }
    }
  );

  // Critical D1 write fences are introduced in migrations after 0001.
  // A schema with the five initial tables but no admission guards must NOT be ready.
  it.each([
    ["trigger","processing_outbox_verified_completion"],
    ["view","processing_redrive_consumer_denials"],
    ["trigger","processing_redrive_consumer_report_authority_guard"],
    ["trigger","processing_redrive_consumer_status_authority_guard"],
    ["trigger","processing_report_active_commission_guard"],
    ["trigger","processing_status_active_commission_guard"]
  ] as const)("fails closed when the required %s %s is absent", async(type,name)=>{
    const f=await signedFixture();
    try{
      const operator=await f.token("operator");
      const complete=await handleApiRequest(f.request(operator),f.env);
      expect(complete.status).toBe(200);
      // The object name is a known literal fixture, never user input.
      f.sqlite.exec(`DROP ${type.toUpperCase()} "${name}"`);
      const response=await handleApiRequest(f.request(operator),f.env);
      expect(response.status).toBe(503);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(await response.json()).toEqual({error:"Service unavailable"});
      expect(f.sqlite.prepare(
        "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name IN ('commissions','commission_members','document_batches','document_versions','audit_events')"
      ).get()).toMatchObject({n:5});
    }finally{f.close();}
  });

  it("fails closed on a D1 error without leaking SQL, token or backend details",async()=>{
    const f=await signedFixture();
    try{
      const operator=await f.token("operator");
      const brokenDb={ prepare: () => {throw new Error("SENSITIVE_SQLITE_INTERNAL");} } as unknown as D1Database;
      const response=await handleApiRequest(f.request(operator),{...f.env,DB:brokenDb});
      expect(response.status).toBe(503);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      const body=await response.text();
      expect(JSON.parse(body)).toEqual({error:"Service unavailable"});
      expect(body).not.toContain("SENSITIVE_SQLITE_INTERNAL");
    }finally{f.close();}
  });
});
