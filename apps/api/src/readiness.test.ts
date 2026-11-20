import { afterEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleApiRequest, type ApiEnv } from "./index";

const ISSUER="https://readiness-audit.cloudflareaccess.com";
const AUDIENCE="folio-readiness-test";
const PATH="https://api.test/api/internal/readiness";
const AUTHORIZED_SUBJECT="operator_readiness";
afterEach(()=>vi.unstubAllGlobals());

async function fixture(){
  const f=makeD1();
  const pair=await generateKeyPair("RS256");
  const publicKey=await exportJWK(pair.publicKey);
  publicKey.kid="synthetic-readiness-key";
  const fetchJwks=vi.fn(async()=>Response.json({keys:[publicKey]}));
  vi.stubGlobal("fetch",fetchJwks);
  const sign=(subject:string)=>new SignJWT({purpose:"synthetic-only"})
    .setProtectedHeader({alg:"RS256",kid:publicKey.kid})
    .setIssuer(ISSUER).setAudience(AUDIENCE).setSubject(subject)
    .setIssuedAt().setExpirationTime("10m").sign(pair.privateKey);
  const list=vi.fn(async()=>({
    objects:[{key:"quarantine/do-not-expose.pdf"}],
    truncated:false
  }));
  const env:ApiEnv={
    DB:f.db,
    DOCUMENTS:{list} as unknown as R2Bucket,
    ACCESS_TEAM_DOMAIN:ISSUER,
    ACCESS_AUD:AUDIENCE,
    READINESS_OPERATOR_SUBJECT:AUTHORIZED_SUBJECT
  };
  const request=(assertion?:string,method="GET",origin?:string)=>new Request(PATH,{
    method,
    headers:{
      ...(assertion?{"Cf-Access-Jwt-Assertion":assertion}:{}),
      ...(origin?{Origin:origin}:{})
    }
  });
  return {...f,env,sign,list,fetchJwks,request};
}

describe("private API storage readiness (not pipeline availability)",()=>{
  it("retains public liveness but requires signed identity for the private readiness path",async()=>{
    const f=await fixture();
    try{
      expect(await (await handleApiRequest(new Request("https://api.test/health"),{})).json())
        .toEqual({status:"ok"});
      const anonymous=await handleApiRequest(f.request(),f.env);
      expect(anonymous.status).toBe(401);
      expect(anonymous.headers.get("Cache-Control")).toBe("no-store");
      expect(f.list).not.toHaveBeenCalled();
      const incorrectMethod=await handleApiRequest(f.request(undefined,"POST"),f.env);
      expect(incorrectMethod.status).toBe(405);
    }finally{f.close();}
  });

  it("fails closed for unconfigured or non-operator identities",async()=>{
    const f=await fixture();
    try{
      const operator=await f.sign(AUTHORIZED_SUBJECT);
      const other=await f.sign("another_member");
      expect((await handleApiRequest(f.request(other),f.env)).status).toBe(404);
      expect((await handleApiRequest(f.request(operator),{
        ...f.env,READINESS_OPERATOR_SUBJECT:undefined
      })).status).toBe(404);
      expect((await handleApiRequest(f.request(operator),{
        ...f.env,READINESS_OPERATOR_SUBJECT:"another_member"
      })).status).toBe(404);
      expect(f.list).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("probes D1 and R2 without disclosing object metadata or claiming the pipeline is ready",async()=>{
    const f=await fixture();
    try{
      const operator=await f.sign(AUTHORIZED_SUBJECT);
      const response=await handleApiRequest(f.request(operator),f.env);
      expect(response.status).toBe(200);
      expect(response.headers.get("Cache-Control")).toContain("no-store");
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      const body=await response.json();
      expect(body).toEqual({
        status:"ready",scope:"api-storage",documentPipeline:"not_verified"
      });
      expect(JSON.stringify(body)).not.toContain("quarantine/");
      expect(JSON.stringify(body)).not.toContain("do-not-expose");
      expect(f.list).toHaveBeenCalledWith({prefix:"quarantine/",limit:1});
      expect(f.list).toHaveBeenCalledTimes(1);
    }finally{f.close();}
  });

  it("never claims readiness when R2 is missing, throws or returns malformed results",async()=>{
    const f=await fixture();
    try{
      const operator=await f.sign(AUTHORIZED_SUBJECT);
      const absent=await handleApiRequest(f.request(operator),{...f.env,DOCUMENTS:undefined});
      expect(absent.status).toBe(503);
      expect(await absent.json()).toEqual({status:"unavailable",scope:"api-storage"});
      expect(f.list).not.toHaveBeenCalled();
      f.list.mockRejectedValueOnce(new Error("secret bucket connection string"));
      const unavailable=await handleApiRequest(f.request(operator),f.env);
      expect(unavailable.status).toBe(503);
      expect(JSON.stringify(await unavailable.json())).not.toContain("secret bucket");
    }finally{f.close();}
  });

  it("fails closed on D1 errors before contacting R2 and never leaks database details",async()=>{
    const f=await fixture();
    try{
      const operator=await f.sign(AUTHORIZED_SUBJECT);
      const badDb={
        prepare:()=>{throw new Error("DATABASE_PASSWORD_SHOULD_NOT_LEAK");}
      } as unknown as D1Database;
      const unavailable=await handleApiRequest(f.request(operator),{...f.env,DB:badDb});
      expect(unavailable.status).toBe(503);
      expect(await unavailable.json()).toEqual({status:"unavailable",scope:"api-storage"});
      expect(f.list).not.toHaveBeenCalled();
      expect(unavailable.headers.get("Cache-Control")).toContain("no-store");
    }finally{f.close();}
  });

  it("blocks cross-site origins and does not probe dependencies when access is denied",async()=>{
    const f=await fixture();
    try{
      const operator=await f.sign(AUTHORIZED_SUBJECT);
      const external=await handleApiRequest(f.request(operator,"GET","https://evil.test"),f.env);
      expect(external.status).toBe(403);
      expect(f.list).not.toHaveBeenCalled();
    }finally{f.close();}
  });
});
