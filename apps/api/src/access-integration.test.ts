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
        VALUES ('c_a','alice','member',1),('c_a','eva','president',1),('c_b','bob','member',1);
      INSERT INTO document_batches(id,commission_id,label)
        VALUES ('b_a','c_a','Obras'),('b_b','c_b','Otros');
      INSERT INTO checklist_items(id,commission_id,area,expected_document)
        VALUES ('item_a','c_a','works','Expediente de obra'),('item_b','c_b','procurement','Contrato B');
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

  it("provisions a pilot batch and checklist using a signed president identity", async () => {
    const f=fixture();
    try {
      const {token}=await tokenFor("eva");
      const env={DB:f.db,ACCESS_TEAM_DOMAIN:issuer,ACCESS_AUD:audience};
      const create=async (path:string,key:string,body:unknown)=>
        handleApiRequest(new Request("https://folio.test"+path,{
          method:"POST",
          headers:{"Cf-Access-Jwt-Assertion":token,"Idempotency-Key":key,
            "Content-Type":"application/json"},
          body:JSON.stringify(body)
        }),env);
      const batch=await create("/api/commissions/c_a/batches","signed_batch_12345",{label:"Lote piloto nuevo"});
      expect(batch.status).toBe(201);
      const checklist=await create("/api/commissions/c_a/checklist/items","signed_check_12345",{
        area:"procurement",expectedDocument:"Contrato específico de obra"
      });
      expect(checklist.status).toBe(201);
      const listed=await call(f.db,token,"/api/commissions/c_a/batches");
      expect(listed.status).toBe(200);
      expect(await listed.json()).toEqual(expect.arrayContaining([expect.objectContaining({label:"Lote piloto nuevo"})]));
      const items=await call(f.db,token,"/api/commissions/c_a/checklist");
      expect(items.status).toBe(200);
      expect(await items.json()).toEqual(expect.arrayContaining([
        expect.objectContaining({expectedDocument:"Contrato específico de obra",status:"pending"})
      ]));
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_provisioning_requests").get())
        .toMatchObject({n:2});
    } finally {f.close();}
  });

  it("routes a signed human draft with real tenant checks and an auditable record", async () => {
    const f=fixture();
    try {
      const {token}=await tokenFor("alice");
      const request=new Request("https://folio.test/api/commissions/c_a/observations/drafts",{
        method:"POST",headers:{"Content-Type":"application/json","Cf-Access-Jwt-Assertion":token,"Idempotency-Key":"draft_signed_001"},
        body:JSON.stringify({title:"Expediente no ubicado",description:"Búsqueda manual realizada en el lote.",checklistItemId:"item_a",batchId:"b_a"})
      });
      const response=await handleApiRequest(request,{DB:f.db,ACCESS_TEAM_DOMAIN:issuer,ACCESS_AUD:audience});
      expect(response.status).toBe(201);
      expect(await response.json()).toMatchObject({status:"draft",authorSubject:"alice"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM observation_evidence").get()).toMatchObject({n:1});
    } finally {f.close();}
  });

  it("uses two distinct signed identities for a final human decision", async () => {
    const f=fixture();
    try {
      const {token:author}=await tokenFor("alice");
      const env={DB:f.db,ACCESS_TEAM_DOMAIN:issuer,ACCESS_AUD:audience};
      const draftRequest=new Request("https://folio.test/api/commissions/c_a/observations/drafts",{
        method:"POST",headers:{"Content-Type":"application/json",
          "Cf-Access-Jwt-Assertion":author,"Idempotency-Key":"signed_draft_321"},
        body:JSON.stringify({title:"Documento ausente",description:"Búsqueda manual documentada.",
          checklistItemId:"item_a",batchId:"b_a"})
      });
      const created=await handleApiRequest(draftRequest,env);
      expect(created.status).toBe(201);
      const {id}=await created.json() as {id:string};
      const submit=new Request(`https://folio.test/api/commissions/c_a/observations/${id}/actions`,{
        method:"POST",headers:{"Content-Type":"application/json",
          "Cf-Access-Jwt-Assertion":author,"Idempotency-Key":"signed_submit_321"},
        body:JSON.stringify({action:"submit"})
      });
      expect((await handleApiRequest(submit,env)).status).toBe(200);
      const {token:reviewer}=await tokenFor("eva");
      const review=new Request(`https://folio.test/api/commissions/c_a/observations/${id}/actions`,{
        method:"POST",headers:{"Content-Type":"application/json",
          "Cf-Access-Jwt-Assertion":reviewer,"Idempotency-Key":"signed_review_321"},
        body:JSON.stringify({action:"validate",note:"Revisé de forma independiente el alcance documentado."})
      });
      const decision=await handleApiRequest(review,env);
      expect(decision.status).toBe(200);
      expect(await decision.json()).toMatchObject({status:"validated",validatedBy:"eva"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:3});
    } finally {f.close();}
  });

  it("enforces signed Access identity for text pages and human page citations", async () => {
    const f=fixture();
    try {
      f.sqlite.exec(`
        INSERT INTO documents(id,commission_id,batch_id,filename)
          VALUES('doc_a','c_a','b_a','Expediente.pdf');
        INSERT INTO document_versions(id,document_id,version_number,sha256,r2_object_key)
          VALUES('ver_a','doc_a',1,'${"a".repeat(64)}','quarantine/private.pdf');
        INSERT INTO document_processing_reports(document_version_id,scanner_name,scanner_report_id,
          scanned_at,source_sha256,manifest_sha256,page_count)
          VALUES('ver_a','test-inspector','test_report_signed_001','2026-11-18T17:30:00.000Z',
          '${"a".repeat(64)}','${"b".repeat(64)}',1);
        INSERT INTO document_pages(document_version_id,page,extracted_text,extraction_status)
          VALUES('ver_a',1,'Texto de expediente comprobado','ready');
        UPDATE document_versions SET extraction_status='ready',page_count=1 WHERE id='ver_a';
      `);
      const {token}=await tokenFor("alice");
      const path="/api/commissions/c_a/documents/ver_a/pages";
      const accessible=await call(f.db,token,path);
      expect(accessible.status).toBe(200);
      expect(await accessible.json()).toMatchObject({pages:[{page:1,text:"Texto de expediente comprobado"}]});
      const denied=await handleApiRequest(new Request("https://folio.test"+path),{
        DB:f.db,ACCESS_TEAM_DOMAIN:issuer,ACCESS_AUD:audience
      });
      expect(denied.status).toBe(401);
      const citation=new Request("https://folio.test/api/commissions/c_a/observations/page-drafts",{
        method:"POST",headers:{"Cf-Access-Jwt-Assertion":token,"Content-Type":"application/json",
          "Idempotency-Key":"signed_page_draft_001"},
        body:JSON.stringify({title:"Referencia documental",
          description:"Revisé personalmente el texto de esta página.",
          documentVersionId:"ver_a",page:1})
      });
      const response=await handleApiRequest(citation,{
        DB:f.db,ACCESS_TEAM_DOMAIN:issuer,ACCESS_AUD:audience
      });
      expect(response.status).toBe(201);
      expect(await response.json()).toMatchObject({
        authorSubject:"alice",evidence:[{
          type:"DOCUMENT_PAGE",documentVersionId:"ver_a",page:1,sha256:"a".repeat(64)
        }]
      });
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
