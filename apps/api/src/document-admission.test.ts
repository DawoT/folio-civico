import {afterEach,describe,expect,it,vi} from "vitest";
import {exportJWK,generateKeyPair,SignJWT} from "jose";
import {makeD1} from "../../../tests/helpers/d1";
import {handleApiRequest,type ApiEnv} from "./index";

const issuer="https://folio-ingest-gate-test.cloudflareaccess.com";
const audience="folio-ingest-gate-synthetic";
const url="https://folio.test/api/commissions/c_a/batches/b_a/documents";
const pdf=new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF");
afterEach(()=>vi.unstubAllGlobals());

async function fixture(){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('c_a','Synthetic Commission A','active'),
      ('c_b','Synthetic Commission B','active');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES ('c_a','author','member',1),
        ('c_a','viewer','observer',1),
        ('c_b','outsider','member',1);
    INSERT INTO document_batches(id,commission_id,label)
      VALUES('b_a','c_a','Synthetic batch');
  `);
  const put=vi.fn(async()=>({key:"quarantine/synthetic.pdf"}));
  const del=vi.fn(async()=>undefined);
  const {privateKey,publicKey}=await generateKeyPair("RS256");
  const jwk=await exportJWK(publicKey);
  jwk.kid="ingest-gate-key";
  vi.stubGlobal("fetch",vi.fn(async()=>Response.json({keys:[jwk]})));
  const env:ApiEnv={
    DB:f.db,DOCUMENTS:{put,delete:del} as unknown as R2Bucket,
    ACCESS_TEAM_DOMAIN:issuer,ACCESS_AUD:audience
  };
  async function jwt(subject:string){
    return new SignJWT({kind:"synthetic-document-intake-gate"})
      .setProtectedHeader({alg:"RS256",kid:jwk.kid})
      .setIssuer(issuer).setAudience(audience).setSubject(subject)
      .setIssuedAt().setExpirationTime("15m").sign(privateKey);
  }
  async function request(subject:string,method="POST",path=url){
    return new Request(path,{
      method,headers:{
        "Cf-Access-Jwt-Assertion":await jwt(subject),
        ...(method==="POST"?{
          "Content-Type":"application/pdf",
          "X-Document-Filename":"expediente-sintetico.pdf",
          "Idempotency-Key":"ingest_gate_synthetic_001"
        }:{})
      },...(method==="POST"?{body:pdf as BodyInit}:{})
    });
  }
  return {...f,put,del,env,jwt,request};
}

describe("S04 manual-only Preview must deny PDF intake by default",()=>{
  it("rejects authenticated POST before any R2 or D1 write when the flag is absent",async()=>{
    const f=await fixture();
    try{
      const response=await handleApiRequest(await f.request("author"),f.env);
      expect(response.status).toBe(503);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(await response.json()).toEqual({error:"Document intake unavailable"});
      expect(f.put).not.toHaveBeenCalled();
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM documents").get()).toEqual({n:0});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:0});
    }finally{f.close();}
  });

  it.each(["false","1","TRUE"," true ","enabled",""])(
    "never treats an ambiguous config value %j as an upload permission",async(value)=>{
      const f=await fixture();
      try{
        const response=await handleApiRequest(await f.request("author"),
          {...f.env,DOCUMENT_UPLOADS_ENABLED:value});
        expect(response.status).toBe(503);
        expect(f.put).not.toHaveBeenCalled();
      }finally{f.close();}
    }
  );

  it("allows explicit synthetic fixture opt-in while keeping idempotency, authorization and listing",async()=>{
    const f=await fixture();
    try{
      const enabled={...f.env,DOCUMENT_UPLOADS_ENABLED:"true"};
      const uploaded=await handleApiRequest(await f.request("author"),enabled);
      expect(uploaded.status).toBe(201);
      expect(await uploaded.json()).toMatchObject({
        repeated:false,ingestStatus:"quarantined",processingStatus:"pending"
      });
      const replay=await handleApiRequest(await f.request("author"),enabled);
      expect(replay.status).toBe(200);
      expect(await replay.json()).toMatchObject({repeated:true});
      expect(f.put).toHaveBeenCalledTimes(1);
      const list=await handleApiRequest(await f.request("author","GET"),f.env);
      expect(list.status).toBe(200);
      expect(await list.json()).toHaveLength(1);
    }finally{f.close();}
  });

  it("blocks a replay when document intake is disabled after an earlier successful upload",async()=>{
    const f=await fixture();
    try {
      const enabled={...f.env,DOCUMENT_UPLOADS_ENABLED:"true"};
      const first=await handleApiRequest(await f.request("author"),enabled);
      expect(first.status).toBe(201);
      const audit=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
      const replay=await handleApiRequest(await f.request("author"),f.env);
      expect(replay.status).toBe(503);
      expect(await replay.json()).toEqual({error:"Document intake unavailable"});
      expect(f.put).toHaveBeenCalledTimes(1);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(audit);
      const list=await handleApiRequest(await f.request("author","GET"),f.env);
      expect(list.status).toBe(200);
      expect(await list.json()).toHaveLength(1);
    }finally{f.close();}
  });

  it("preserves signed authentication, commission isolation, and read-only access",async()=>{
    const f=await fixture();
    try{
      const anonymous=await handleApiRequest(new Request(url,{method:"POST",body:pdf as BodyInit}),f.env);
      expect(anonymous.status).toBe(401);
      const outsider=await handleApiRequest(await f.request("outsider"),{
        ...f.env,DOCUMENT_UPLOADS_ENABLED:"true"
      });
      expect(outsider.status).toBe(404);
      const readonly=await handleApiRequest(await f.request("viewer"),{
        ...f.env,DOCUMENT_UPLOADS_ENABLED:"true"
      });
      expect(readonly.status).toBe(403);
      const read=await handleApiRequest(await f.request("viewer","GET"),f.env);
      expect(read.status).toBe(200);
      expect(await read.json()).toEqual([]);
      expect(f.put).not.toHaveBeenCalled();
    }finally{f.close();}
  });
});
