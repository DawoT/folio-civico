import {afterEach,describe,expect,it,vi} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {revocationFixture} from "../../../packages/auth/src/revocation-fixture.test-helper";
import {syntheticOperatorAuthorization} from "../../../packages/auth/src/signed-fixture.test-helper";
import {persistDocumentUpload} from "../../../packages/data/src/documents";
import {openRecoveryReview,decideRecoveryReview} from "../../../packages/data/src/recovery-review";
import {handleIsolatedOperatorRequest,type IsolatedOperatorConfig} from "./isolated-host";

afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});

const PATH="https://operator.local/internal/operations/";
const SHA="a".repeat(64);

function request(kind:"revocations"|"redrives",body:unknown,headers:Record<string,string>={}){
  return new Request(PATH+kind,{
    method:"POST",
    headers:{"Content-Type":"application/json",...headers},
    body:JSON.stringify(body)
  });
}
function revocationHeaders(f:Awaited<ReturnType<typeof revocationFixture>>){
  return {
    "Cf-Access-Jwt-Assertion":f.evidence.actorAccessRequest.headers.get("Cf-Access-Jwt-Assertion")!,
    "X-Folio-Approver-Access-Jwt":f.evidence.approverAccessRequest.headers.get("Cf-Access-Jwt-Assertion")!,
    "X-Folio-Incident-Approval-Jws":f.evidence.approvalJwt
  };
}
function redriveHeaders(f:Awaited<ReturnType<typeof syntheticOperatorAuthorization>>){
  return {
    "Cf-Access-Jwt-Assertion":f.evidence.accessRequest.headers.get("Cf-Access-Jwt-Assertion")!,
    "X-Folio-Redrive-Approval-Jws":f.evidence.approvalJwt,
    "X-Folio-Inspector-Release-Jws":f.evidence.releaseJwt
  };
}
const base=(db:D1Database):IsolatedOperatorConfig=>({
  mode:"synthetic-offline-only",db,allowLegacyCombinedRevocations:true,
  allowLegacyDirectRedrives:true
});
async function redriveFixture(db:D1Database,sqlite:ReturnType<typeof makeD1>["sqlite"]){
  sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES ('c_a','Commission fake','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','president','president',1),('c_a','reviewer','member',1);
    INSERT INTO document_batches(id,commission_id,label)
      VALUES ('batch_a','c_a','Pilot');
  `);
  await persistDocumentUpload(db,{
    commissionId:"c_a",batchId:"batch_a",subject:"president",
    documentId:"doc_a",versionId:"version_a",sha256:SHA,
    r2Key:"quarantine/opaque-id.pdf",filename:"synthetic.pdf",
    idempotencyKey:"document_upload_001"
  });
  sqlite.exec(`
    UPDATE document_processing_outbox
    SET state='sent',attempts=10,last_sent_at='2026-11-19T12:00:00.000Z'
    WHERE document_version_id='version_a'
  `);
  const opened=await openRecoveryReview(db,{
    commissionId:"c_a",versionId:"version_a",sourceSha256:SHA,
    actorSubject:"president",incidentRef:"INC_20261119_001",
    requestKey:"recovery_open_001"
  });
  await decideRecoveryReview(db,{
    commissionId:"c_a",reviewId:opened.id,actorSubject:"reviewer",
    decision:"endorse",requestKey:"recovery_endorse_001",
    rationale:"Synthetic independent decision to evaluate an exhausted case."
  });
  const f=await syntheticOperatorAuthorization({reviewId:opened.id});
  return {f,input:{
    commissionId:"c_a",reviewId:opened.id,
    requestKey:"operator_redrive_0001",operatorApprovalRef:"OPR_20261119_001"
  }};
}

describe("R2.9 · isolated private operator HTTP adapter (not deployed)",()=>{
  it("defaults to disabled and does not parse, fetch JWKS or query D1",async()=>{
    const f=makeD1();
    try{
      const fetchSpy=vi.spyOn(globalThis,"fetch");
      const r=await handleIsolatedOperatorRequest(
        request("revocations",{kind:"image"}),{db:f.db}
      );
      expect(r.status).toBe(503);
      expect(r.headers.get("Cache-Control")).toBe("no-store");
      expect(await r.text()).not.toMatch(/incident|secret|token/i);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
    }finally{f.close();}
  });

  it("rejects routes, browser Origins/cookies, incorrect media, unknown input and oversized bodies before authorization",async()=>{
    const f=makeD1();
    try {
      const x=await revocationFixture();
      const cfg={...base(f.db),revocationTrust:x.config};
      const headers=revocationHeaders(x);
      const cases:[Request,number][]=[
        [new Request(PATH+"unknown",{method:"POST"}),404],
        [new Request(PATH+"revocations",{method:"GET"}),405],
        [request("revocations",x.scope,{...headers,Origin:"https://evil.example"}),403],
        [request("revocations",x.scope,{...headers,Cookie:"session=unsafe"}),403],
        [request("revocations",x.scope,{...headers,"Content-Type":"text/plain"}),415],
        [request("revocations",{...x.scope,operatorSubject:"spoof"},headers),400],
        [request("revocations",{...x.scope,reason:"x".repeat(9000)},headers),413],
        [new Request(PATH+"revocations?override=true",{method:"POST",headers,body:"{}"}),404]
      ];
      for(const [r,status] of cases){
        const result=await handleIsolatedOperatorRequest(r,cfg);
        expect(result.status).toBe(status);
        expect(result.headers.get("Access-Control-Allow-Origin")).toBeNull();
        expect(result.headers.get("Cache-Control")).toBe("no-store");
      }
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
    }finally{f.close();}
  });

  it("registers a signed revocation once; replay and all returned headers exclude JWTs and rationale",async()=>{
    const f=makeD1();
    try{
      const x=await revocationFixture();
      const cfg={...base(f.db),revocationTrust:x.config};
      const first=await handleIsolatedOperatorRequest(request("revocations",x.scope,revocationHeaders(x)),cfg);
      expect(first.status).toBe(200);
      expect(await first.json()).toEqual({registered:true,replayed:false});
      const second=await handleIsolatedOperatorRequest(request("revocations",x.scope,revocationHeaders(x)),cfg);
      expect(second.status).toBe(200);
      expect(await second.json()).toEqual({registered:true,replayed:true});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocation_actions").get()).toMatchObject({n:1});
      for(const value of [first.headers.toString(),second.headers.toString()]){
        expect(value).not.toContain(x.evidence.approvalJwt);
        expect(value).not.toContain(x.scope.reason);
      }
    }finally{f.close();}
  });

  it("rejects forged approver JWT, JWS or modified revocation scope without writes",async()=>{
    const f=makeD1();
    try{
      const x=await revocationFixture();
      const cfg={...base(f.db),revocationTrust:x.config};
      for(const headers of [
        {...revocationHeaders(x),"X-Folio-Approver-Access-Jwt":"fake"},
        {...revocationHeaders(x),"X-Folio-Incident-Approval-Jws":"fake"},
        {...revocationHeaders(x),"Cf-Access-Jwt-Assertion":"fake"}
      ]){
        expect((await handleIsolatedOperatorRequest(request("revocations",x.scope,headers),cfg)).status).toBe(403);
      }
      expect((await handleIsolatedOperatorRequest(request("revocations",{
        ...x.scope,requestKey:"substituted_request_001"
      },revocationHeaders(x)),cfg)).status).toBe(403);
      expect((await handleIsolatedOperatorRequest(request("revocations",x.scope,{
        "Cf-Access-Jwt-Assertion":revocationHeaders(x)["Cf-Access-Jwt-Assertion"]
      }),cfg)).status).toBe(403);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get()).toMatchObject({n:0});
    }finally{f.close();}
  });

  it("executes one synthetic Queue redrive through signed preflight, preserves outbox 10, never repeats enqueue",async()=>{
    const f=makeD1();
    const sent:unknown[]=[];
    try{
      const {f:x,input}=await redriveFixture(f.db,f.sqlite);
      const cfg:IsolatedOperatorConfig={
        ...base(f.db),redriveTrust:x.config,
        queue:{send:vi.fn(async(value:unknown)=>{sent.push(value);})},
        runtimeInspectorImageDigest:x.config.requiredImageDigest
      };
      const first=await handleIsolatedOperatorRequest(request("redrives",input,redriveHeaders(x)),cfg);
      expect(first.status).toBe(200);
      const payload=await first.json() as Record<string,unknown>;
      expect(payload).toMatchObject({state:"sent",replayed:false});
      expect(JSON.stringify(payload)).not.toContain(SHA);
      expect(JSON.stringify(payload)).not.toContain("quarantine/");
      const twice=await handleIsolatedOperatorRequest(request("redrives",input,redriveHeaders(x)),cfg);
      expect(twice.status).toBe(200);
      expect(await twice.json()).toEqual({...payload,replayed:true});
      expect(sent).toEqual([{kind:"folio.process.pdf",versionId:"version_a",sourceSha256:SHA}]);
      expect(f.sqlite.prepare("SELECT attempts FROM document_processing_outbox WHERE document_version_id='version_a'").get()).toMatchObject({attempts:10});
    }finally{f.close();}
  });

  it("treats an ambiguous synthetic Queue rejection as one uncertain reservation and never resends",async()=>{
    const f=makeD1();
    const send=vi.fn(async()=>{throw new Error("Queue may have accepted before disconnect");});
    try{
      const {f:x,input}=await redriveFixture(f.db,f.sqlite);
      const cfg:IsolatedOperatorConfig={
        ...base(f.db),redriveTrust:x.config,queue:{send},
        runtimeInspectorImageDigest:x.config.requiredImageDigest
      };
      const first=await handleIsolatedOperatorRequest(request("redrives",input,redriveHeaders(x)),cfg);
      expect(first.status).toBe(202);
      const result=await first.json() as Record<string,unknown>;
      expect(result).toMatchObject({state:"uncertain",replayed:false});
      const second=await handleIsolatedOperatorRequest(request("redrives",input,redriveHeaders(x)),cfg);
      expect(second.status).toBe(202);
      expect(await second.json()).toEqual({...result,replayed:true});
      expect(send).toHaveBeenCalledTimes(1);
      expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox WHERE document_version_id='version_a'").get())
        .toMatchObject({state:"sent",attempts:10});
    }finally{f.close();}
  });

  it("a signed image revocation registered through the private adapter immediately blocks redrive",async()=>{
    const f=makeD1();
    const send=vi.fn(async()=>undefined);
    try{
      const {f:approved,input}=await redriveFixture(f.db,f.sqlite);
      const incident=await revocationFixture({kind:"image",
        target:approved.config.requiredImageDigest!});
      const cfg:IsolatedOperatorConfig={
        ...base(f.db),revocationTrust:incident.config,
        redriveTrust:approved.config,queue:{send},
        runtimeInspectorImageDigest:approved.config.requiredImageDigest
      };
      // Both independent Access issuers have distinct pinned RSA key IDs.
      vi.stubGlobal("fetch",vi.fn(async()=>Response.json({
        keys:[incident.keys.accessJwk,approved.keys.accessJwk]
      })));
      const revoked=await handleIsolatedOperatorRequest(request(
        "revocations",incident.scope,revocationHeaders(incident)),cfg);
      expect(revoked.status).toBe(200);
      const blocked=await handleIsolatedOperatorRequest(request(
        "redrives",input,redriveHeaders(approved)),cfg);
      expect(blocked.status).toBe(403);
      expect(send).not.toHaveBeenCalled();
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_manual_redrives").get())
        .toMatchObject({n:0});
    }finally{f.close();}
  });

  it("returns a generic no-store failure when the private database is unavailable",async()=>{
    const f=makeD1();
    try{
      const x=await revocationFixture();
      const broken={
        prepare:()=>{throw new Error("DB credentials and private secret never leave server");},
        batch:()=>{throw new Error("not reachable");}
      } as unknown as D1Database;
      const r=await handleIsolatedOperatorRequest(request(
        "revocations",x.scope,revocationHeaders(x)),{
        ...base(broken),revocationTrust:x.config
      });
      expect(r.status).toBe(503);
      const body=await r.text();
      expect(body).not.toContain("DB credentials");
      expect(body).not.toContain(x.scope.reason);
      expect(body).not.toContain(x.evidence.approvalJwt);
      expect(r.headers.get("Cache-Control")).toBe("no-store");
    }finally{f.close();}
  });

  it("never sends without Queue, release digest or authentic redrive approval; denies revoked signed release",async()=>{
    const f=makeD1();
    const sent:unknown[]=[];
    try{
      const {f:x,input}=await redriveFixture(f.db,f.sqlite);
      const cfg:IsolatedOperatorConfig={
        ...base(f.db),redriveTrust:x.config,
        runtimeInspectorImageDigest:x.config.requiredImageDigest,
        queue:{send:vi.fn(async(v:unknown)=>{sent.push(v);})}
      };
      expect((await handleIsolatedOperatorRequest(request("redrives",input,redriveHeaders(x)),
        {...cfg,queue:undefined})).status).toBe(503);
      expect((await handleIsolatedOperatorRequest(request("redrives",input,redriveHeaders(x)),
        {...cfg,runtimeInspectorImageDigest:"sha256:"+"0".repeat(64)})).status).toBe(503);
      expect((await handleIsolatedOperatorRequest(request("redrives",input,{
        ...redriveHeaders(x),"X-Folio-Inspector-Release-Jws":"bogus"
      }),cfg)).status).toBe(403);
      expect((await handleIsolatedOperatorRequest(request("redrives",{...input,operatorSubject:"forged"},redriveHeaders(x)),cfg)).status).toBe(400);
      expect(sent).toHaveLength(0);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_manual_redrives").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
});
