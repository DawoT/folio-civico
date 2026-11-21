import {afterEach, describe, expect, it, vi} from "vitest";
import {exportJWK, generateKeyPair, SignJWT} from "jose";
import {makeD1} from "../../../tests/helpers/d1";
import {handleApiRequest, type ApiEnv} from "./index";

const issuer="https://folio-review-count-test.cloudflareaccess.com";
const audience="folio-review-count-local";
const path="/api/commissions/a/observations/reviewable-count";
afterEach(()=>vi.unstubAllGlobals());

async function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('a','Synthetic A','active'),('b','Synthetic B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('a','reviewer','president',1),('a','author','member',1),
      ('a','observer','observer',1),('a','revoked','member',0),
      ('b','outsider','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('batch','a','Synthetic');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item','a','works','Synthetic');
  `);
  const add=f.sqlite.prepare(`
    INSERT INTO observations(id,commission_id,author_subject,title,description)
      VALUES(?, 'a','author','Synthetic review','Evidence')
  `);
  const evidence=f.sqlite.prepare(`
    INSERT INTO observation_evidence(id,observation_id,type,reference_json)
      VALUES(?,?,'SEARCH_SCOPE',?)
  `);
  const submit=f.sqlite.prepare(`
    UPDATE observations SET status='in_review',submitted_by='author',
      submitted_at=CURRENT_TIMESTAMP,submit_request_key=? WHERE id=?
  `);
  for(let i=0;i<31;i++) {
    const id="review_"+i;
    add.run(id);
    evidence.run("e_"+id,id,JSON.stringify({
      type:"SEARCH_SCOPE",commissionId:"a",checklistItemId:"item",
      batchId:"batch",reviewerId:"author",searchedAt:"2026-11-20T12:00:00.000Z"
    }));
    submit.run("submit_"+id,id);
  }

  const {publicKey,privateKey}=await generateKeyPair("RS256");
  const jwk=await exportJWK(publicKey);
  jwk.kid="count-key";
  vi.stubGlobal("fetch",vi.fn(async()=>Response.json({keys:[jwk]})));
  const env:ApiEnv={DB:f.db,ACCESS_TEAM_DOMAIN:issuer,ACCESS_AUD:audience};
  async function jwt(subject:string,expired=false) {
    const token=new SignJWT({purpose:"synthetic-review-count-test"})
      .setProtectedHeader({alg:"RS256",kid:jwk.kid})
      .setIssuer(issuer).setAudience(audience).setSubject(subject)
      .setIssuedAt();
    return token.setExpirationTime(expired
      ? Math.floor(Date.now()/1000)-60 : "15m").sign(privateKey);
  }
  async function call(subject:string,url=path,method="GET",expired=false) {
    return handleApiRequest(new Request("https://folio.test"+url,{
      method,headers:{"Cf-Access-Jwt-Assertion":await jwt(subject,expired)}
    }),env);
  }
  return {...f,env,jwt,call};
}

describe("full Worker reviewable-count route with verified Access JWT",()=>{
  it("does not turn a named endpoint into an observation ID and returns all 31 rows",async()=>{
    const f=await fixture();
    try{
      const response=await f.call("reviewer");
      expect(response.status).toBe(200);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(await response.json()).toEqual({commissionId:"a",count:31});
    }finally{f.close();}
  });

  it("requires cryptographically verified identity, not user-controlled headers",async()=>{
    const f=await fixture();
    try{
      const anonymous=await handleApiRequest(
        new Request("https://folio.test"+path),f.env);
      expect(anonymous.status).toBe(401);
      expect(await anonymous.json()).toEqual({error:"Unauthorized"});
      const forged=await handleApiRequest(new Request("https://folio.test"+path,{
        headers:{"Cf-Access-Authenticated-User-Email":"reviewer@fake.test"}
      }),f.env);
      expect(forged.status).toBe(401);
      const expired=await f.call("reviewer",path,"GET",true);
      expect(expired.status).toBe(401);
    }finally{f.close();}
  });

  it("does not expose a count to other commissions, revoked or nonexistent members",async()=>{
    const f=await fixture();
    try{
      for(const subject of ["outsider","revoked","absent"]) {
        const response=await f.call(subject);
        expect(response.status).toBe(404);
        expect(await response.json()).toEqual({error:"Not found"});
      }
      expect((await f.call("reviewer",
        "/api/commissions/b/observations/reviewable-count")).status).toBe(404);
    }finally{f.close();}
  });

  it("returns legitimate zero to active observers and the author but never grants write access",async()=>{
    const f=await fixture();
    try{
      for(const subject of ["observer","author"]) {
        const response=await f.call(subject);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({commissionId:"a",count:0});
      }
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='a'");
      const closed=await f.call("reviewer");
      expect(closed.status).toBe(200);
      expect(await closed.json()).toEqual({commissionId:"a",count:0});
    }finally{f.close();}
  });

  it("rejects POST, filters and malformed commission paths without side effects",async()=>{
    const f=await fixture();
    try{
      const before=f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get();
      expect((await f.call("reviewer",path,"POST")).status).toBe(405);
      expect((await f.call("reviewer",path+"?limit=25")).status).toBe(400);
      expect((await f.call("reviewer",
        "/api/commissions/a%2Fb/observations/reviewable-count")).status).toBe(404);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get())
        .toEqual(before);
    }finally{f.close();}
  });
});
