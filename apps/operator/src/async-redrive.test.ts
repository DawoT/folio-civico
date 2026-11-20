import {afterEach,describe,expect,it,vi} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {syntheticOperatorAuthorization} from "../../../packages/auth/src/signed-fixture.test-helper";
import {persistDocumentUpload} from "../../../packages/data/src/documents";
import {openRecoveryReview,decideRecoveryReview} from "../../../packages/data/src/recovery-review";
import {handleIsolatedOperatorRequest,type IsolatedOperatorConfig} from "./isolated-host";

afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});
const ENDPOINT="https://operator.local/internal/operations/";
const SHA="a".repeat(64);
const APPROVER="redrive_approver_independent_001";
function post(route:string,data:unknown,headers:Record<string,string>={}){
  return new Request(ENDPOINT+route,{
    method:"POST",headers:{"Content-Type":"application/json",...headers},
    body:JSON.stringify(data)
  });
}
async function fixture(){
  const d=makeD1();
  d.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES ('c_a','Test commission','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','president','president',1),('c_a','reviewer','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('batch_a','c_a','Sample');
  `);
  await persistDocumentUpload(d.db,{
    commissionId:"c_a",batchId:"batch_a",subject:"president",
    documentId:"doc_a",versionId:"version_a",sha256:SHA,
    r2Key:"quarantine/private-original.pdf",filename:"synthetic.pdf",
    idempotencyKey:"upload_async_redrive_001"
  });
  d.sqlite.exec(`
    UPDATE document_processing_outbox SET state='sent',attempts=10,
      last_sent_at='2026-11-19T12:00:00.000Z' WHERE document_version_id='version_a'
  `);
  const review=await openRecoveryReview(d.db,{
    commissionId:"c_a",versionId:"version_a",sourceSha256:SHA,
    actorSubject:"president",incidentRef:"INC_20261119_777",
    requestKey:"review_open_redrive_001"
  });
  await decideRecoveryReview(d.db,{
    commissionId:"c_a",reviewId:review.id,
    actorSubject:"reviewer",decision:"endorse",
    requestKey:"review_endorse_redrive_001",
    rationale:"Independent review for synthetic operator recovery case."
  });
  const signed=await syntheticOperatorAuthorization({reviewId:review.id});
  const approverJwt=await signed.signing("access",{sub:APPROVER});
  const config={...signed.config,configuredRedriveApproverSubject:APPROVER};
  const send=vi.fn(async (_message:unknown)=>undefined);
  const env:IsolatedOperatorConfig={
    db:d.db,mode:"synthetic-offline-only",redriveTrust:config,
    queue:{send},runtimeInspectorImageDigest:config.requiredImageDigest
  };
  const input={...signed.scope};
  const operatorHeader={"Cf-Access-Jwt-Assertion":
    signed.evidence.accessRequest.headers.get("Cf-Access-Jwt-Assertion")!};
  const approverHeader={"Cf-Access-Jwt-Assertion":approverJwt};
  const propose=async()=>handleIsolatedOperatorRequest(
    post("redrive-proposals",input,operatorHeader),env
  );
  const approvalJwt=(pendingId:string,changes:Record<string,unknown>={})=>
    signed.signing("approval",{
      approverSubject:APPROVER,proposalId:pendingId,sub:APPROVER,...changes
    });
  const approve=(pendingId:string,jws:string,headers=approverHeader)=>
    handleIsolatedOperatorRequest(post("redrive-approvals",
      {requestId:pendingId},{
        ...headers,"X-Folio-Redrive-Approval-Jws":jws
      }),env);
  const execute=(pendingId:string,jws:string,options={
    config:env,headers:operatorHeader,releaseJwt:signed.evidence.releaseJwt
  })=>handleIsolatedOperatorRequest(post("redrive-executions",
      {requestId:pendingId},{
        ...options.headers,"X-Folio-Redrive-Approval-Jws":jws,
        "X-Folio-Inspector-Release-Jws":options.releaseJwt
      }),options.config);
  const counts=()=>({
    proposals:d.sqlite.prepare("SELECT count(*) AS n FROM processing_async_redrive_requests").get() as {n:number},
    approvals:d.sqlite.prepare("SELECT count(*) AS n FROM processing_async_redrive_approvals").get() as {n:number},
    sends:d.sqlite.prepare("SELECT count(*) AS n FROM processing_manual_redrives").get() as {n:number}
  });
  return {...d,env,input,send,signed,operatorHeader,approverHeader,propose,approve,execute,approvalJwt,counts};
}
function insertSyntheticAuditedRevocation(
  f:Awaited<ReturnType<typeof fixture>>,kind:"operator"|"image",target:string
):void {
  // Simulates the already-verified private R2.8 incident registrar; never an
  // unauthenticated user path. Both immutable rows are required by D1.
  f.sqlite.prepare(`
    INSERT INTO processing_redrive_revocation_actions(
      actor_subject,request_key,kind,target,incident_ref,approver_subject,
      target_sha256,reason_sha256,approval_sha256,approval_key_thumbprint,payload_sha256
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
  `).run("incident_actor","approved_"+kind+"_redrive_001",kind,target,
    "INC_REDRIVE_BLOCK_001","incident_approver","a".repeat(64),
    "b".repeat(64),"c".repeat(64),"A".repeat(43),"d".repeat(64));
  f.sqlite.prepare(`
    INSERT INTO processing_redrive_revocations(kind,target,incident_ref)
    VALUES(?,?,?)
  `).run(kind,target,"INC_REDRIVE_BLOCK_001");
}

describe("R2.11 · independent asynchronous redrive authority",()=>{
  it("SQL denies a reservation if institutional invalidation arrives after preflight but before atomic insert",async()=>{
    const f=await fixture();
    try{
      f.env.institutionalGate={reader:{readCurrentEvidence:async(query:Record<string,unknown>)=>{
        const t=Math.floor(Date.now()/1000);
        return {...query,revision:15,status:"open",decision:"approved",
          reviewerSubject:query.approverSubject,checkedAt:t,
          reviewedAt:t-5,mfaVerifiedAt:t-10,validUntil:t+60};
      }}};
      const id=(await (await f.propose()).json() as {id:string}).id;
      const jwt=await f.approvalJwt(id);
      expect((await f.approve(id,jwt)).status).toBe(200);
      let injected=false;
      const raced={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          if(!injected){
            injected=true;
            f.sqlite.prepare(`
              INSERT INTO processing_institutional_approval_invalidations(
                purpose,request_id,case_revision,reason,evidence_sha256
              ) VALUES('redrive',?,15,'case_closed',?)
            `).run(id,"d".repeat(64));
          }
          return f.db.batch(statements);
        }
      } as unknown as D1Database;
      const response=await f.execute(id,jwt,{
        config:{...f.env,db:raced},headers:f.operatorHeader,
        releaseJwt:f.signed.evidence.releaseJwt
      });
      expect(injected).toBe(true);
      expect(response.status).toBe(409);
      expect(f.counts().sends).toEqual({n:0});
      expect(f.send).not.toHaveBeenCalled();
      expect(f.sqlite.prepare(
        "SELECT count(*) AS n FROM processing_manual_redrives"
      ).get()).toMatchObject({n:0});
    }finally{f.close();}
  });


  it("denies an institutionally invalidated approved redrive before Queue reservation",async()=>{
    const f=await fixture();
    try{
      const reader={readCurrentEvidence:async(query:Record<string,unknown>)=>{
        const t=Math.floor(Date.now()/1000);
        return {...query,revision:9,status:"open",decision:"approved",
          reviewerSubject:query.approverSubject,checkedAt:t,
          reviewedAt:t-4,mfaVerifiedAt:t-10,validUntil:t+70};
      }};
      f.env.institutionalGate={reader};
      const id=(await (await f.propose()).json() as {id:string}).id;
      const jwt=await f.approvalJwt(id);
      expect((await f.approve(id,jwt)).status).toBe(200);
      f.sqlite.prepare(`
        INSERT INTO processing_institutional_approval_invalidations(
          purpose,request_id,case_revision,reason,evidence_sha256
        ) VALUES('redrive',?,9,'case_closed',?)
      `).run(id,"d".repeat(64));
      const result=await f.execute(id,jwt);
      expect(result.status).toBe(403);
      expect(f.counts().sends).toEqual({n:0});
      expect(f.send).not.toHaveBeenCalled();
      expect((await f.approve(id,jwt)).status).toBe(403);
    }finally{f.close();}
  });

  it("halts a reserved redrive if institutional invalidation races after D1 reservation",async()=>{
    const f=await fixture();
    try{
      f.env.institutionalGate={reader:{readCurrentEvidence:async(query:Record<string,unknown>)=>{
        const t=Math.floor(Date.now()/1000);
        return {...query,revision:11,status:"open",decision:"approved",
          reviewerSubject:query.approverSubject,checkedAt:t,
          reviewedAt:t-2,mfaVerifiedAt:t-3,validUntil:t+70};
      }}};
      const id=(await (await f.propose()).json() as {id:string}).id;
      const jwt=await f.approvalJwt(id);
      expect((await f.approve(id,jwt)).status).toBe(200);
      let injected=false;
      const racing={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          const result=await f.db.batch(statements);
          if(!injected){
            injected=true;
            f.sqlite.prepare(`
              INSERT INTO processing_institutional_approval_invalidations(
                purpose,request_id,case_revision,reason,evidence_sha256
              ) VALUES('redrive',?,11,'case_closed',?)
            `).run(id,"d".repeat(64));
          }
          return result;
        }
      } as unknown as D1Database;
      const res=await f.execute(id,jwt,{
        config:{...f.env,db:racing},headers:f.operatorHeader,
        releaseJwt:f.signed.evidence.releaseJwt
      });
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({state:"halted",replayed:false});
      expect(injected).toBe(true);
      expect(f.send).not.toHaveBeenCalled();
      expect(f.sqlite.prepare("SELECT state FROM processing_manual_redrives").get())
        .toMatchObject({state:"halted"});
      expect((await f.execute(id,jwt)).status).toBe(403);
      expect(f.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });


  it("D1 prevents downgrading a protected redrive and direct status approval with no receipt",async()=>{
    const f=await fixture();
    try{
      f.env.institutionalGate={};
      const id=(await (await f.propose()).json() as {id:string}).id;
      expect(()=>f.sqlite.prepare(`
        UPDATE processing_async_redrive_requests
        SET institutional_gate_required=0 WHERE id=?
      `).run(id)).toThrow(/INSTITUTIONAL_GATE_IMMUTABLE/);
      expect(()=>f.sqlite.prepare(`
        UPDATE processing_async_redrive_requests
        SET status='approved',approver_subject=?,approval_sha256=?,
          approval_key_thumbprint=?,approved_at=unixepoch() WHERE id=?
      `).run(APPROVER,"b".repeat(64),"A".repeat(43),id))
        .toThrow(/INSTITUTIONAL_EVIDENCE_REQUIRED/);
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
      expect(f.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });


  it("binds a gated redrive approval to an immutable D1 version and requires the same version before Queue",async()=>{
    const f=await fixture();
    try{
      let revision=22;
      const reader={readCurrentEvidence:async(query:Record<string,unknown>)=>{
        const t=Math.floor(Date.now()/1000);
        return {...query,revision,status:"open",decision:"approved",
          reviewerSubject:query.approverSubject,
          checkedAt:t,reviewedAt:t-4,mfaVerifiedAt:t-9,validUntil:t+60};
      }};
      f.env.institutionalGate={reader};
      const proposed=await f.propose();
      expect(proposed.status).toBe(202);
      const id=(await proposed.json() as {id:string}).id;
      expect(f.sqlite.prepare(`
        SELECT institutional_gate_required AS required
        FROM processing_async_redrive_requests WHERE id=?
      `).get(id)).toMatchObject({required:1});
      const jwt=await f.approvalJwt(id);
      f.env.institutionalGate=undefined;
      expect((await f.approve(id,jwt)).status).toBe(503);
      f.env.institutionalGate={reader};
      expect((await f.approve(id,jwt)).status).toBe(200);
      const receipt=f.sqlite.prepare(`
        SELECT purpose,case_revision AS revision,approval_sha256 AS digest
        FROM processing_institutional_approval_evidence WHERE request_id=?
      `).get(id);
      expect(receipt).toMatchObject({
        purpose:"redrive",revision:22,digest:expect.stringMatching(/^[a-f0-9]{64}$/)
      });
      expect(JSON.stringify(receipt)).not.toContain(jwt);
      f.env.institutionalGate=undefined;
      expect((await f.execute(id,jwt)).status).toBe(503);
      revision=23;
      f.env.institutionalGate={reader};
      expect((await f.execute(id,jwt)).status).toBe(403);
      expect(f.send).not.toHaveBeenCalled();
      revision=22;
      expect((await f.execute(id,jwt)).status).toBe(200);
      expect(f.send).toHaveBeenCalledOnce();
    }finally{f.close();}
  });

  it("institutional evidence gate checks approval AND latest status before Queue execution",async()=>{
    const f=await fixture();
    try{
      const id=(await (await f.propose()).json() as {id:string}).id;
      const signed=await f.approvalJwt(id);
      f.env.institutionalGate={};
      expect((await f.approve(id,signed)).status).toBe(503);
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
      let status="open",outage=false;
      const source=vi.fn(async(query:Record<string,unknown>)=>{
        if(outage)throw new Error("institutional service unavailable");
        const t=Math.floor(Date.now()/1000);
        return {...query,revision:9,status,decision:"approved",
          reviewerSubject:query.approverSubject,checkedAt:t,
          reviewedAt:t-4,mfaVerifiedAt:t-10,validUntil:t+90};
      });
      f.env.institutionalGate={reader:{readCurrentEvidence:source}};
      expect((await f.approve(id,signed)).status).toBe(200);
      expect(source).toHaveBeenCalledWith(expect.objectContaining({
        purpose:"redrive",caseRef:f.input.approvalRef,requestId:id,
        approverSubject:APPROVER,scopeDigest:expect.stringMatching(/^[a-f0-9]{64}$/)
      }));
      status="closed";
      expect((await f.execute(id,signed)).status).toBe(403);
      outage=true;
      expect((await f.execute(id,signed)).status).toBe(503);
      expect(f.send).not.toHaveBeenCalled();
      expect(f.counts().sends).toEqual({n:0});
      outage=false;
      status="open";
      expect((await f.execute(id,signed)).status).toBe(200);
      expect(f.send).toHaveBeenCalledOnce();
    }finally{f.close();}
  });

  it("requires operator proposal, distinct approver Access and signed JWS, then operator executes exactly once",async()=>{
    const f=await fixture();
    try{
      const proposed=await f.propose();
      expect(proposed.status).toBe(202);
      const p=await proposed.json() as {id:string;status:string;replayed:boolean};
      expect(p).toMatchObject({status:"pending",replayed:false});
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
      const jwt=await f.approvalJwt(p.id);
      const approved=await f.approve(p.id,jwt);
      expect(approved.status).toBe(200);
      expect(await approved.json()).toEqual({status:"approved",replayed:false});
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:1},sends:{n:0}});
      const first=await f.execute(p.id,jwt);
      expect(first.status).toBe(200);
      const result=await first.json() as Record<string,unknown>;
      expect(result).toMatchObject({state:"sent",replayed:false});
      const repeated=await f.execute(p.id,jwt);
      expect(repeated.status).toBe(200);
      expect(await repeated.json()).toEqual({...result,replayed:true});
      expect(f.send).toHaveBeenCalledOnce();
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:1},sends:{n:1}});
      const row=f.sqlite.prepare(`
        SELECT r.state AS state,p.status AS proposalStatus,
          r.async_request_id AS requestId, p.approver_subject AS approver
        FROM processing_manual_redrives r
        JOIN processing_async_redrive_requests p ON p.id=r.async_request_id
      `).get();
      expect(row).toMatchObject({state:"sent",requestId:p.id,proposalStatus:"approved",approver:"redrive_approver_independent_001"});
      const persisted=JSON.stringify(f.sqlite.prepare("SELECT * FROM processing_async_redrive_requests").all());
      expect(persisted).not.toContain(jwt);
      expect(persisted).not.toContain(f.signed.evidence.accessRequest.headers.get("Cf-Access-Jwt-Assertion")!);
      expect(persisted).not.toContain(f.signed.evidence.releaseJwt);
      expect(JSON.stringify(result)).not.toContain("quarantine/");
      expect(JSON.stringify(result)).not.toContain(SHA);
    }finally{f.close();}
  });

  it("fails closed on omitted, altered or swapped principals and never creates an approved row",async()=>{
    const f=await fixture();
    try{
      expect((await handleIsolatedOperatorRequest(post("redrive-proposals",f.input),f.env)).status).toBe(403);
      const p=await (await f.propose()).json() as {id:string};
      const jwt=await f.approvalJwt(p.id);
      for(const headers of [
        f.operatorHeader,
        {"Cf-Access-Jwt-Assertion":"bogus"}
      ]){
        expect((await f.approve(p.id,jwt,headers)).status).toBe(403);
      }
      expect((await f.approve(p.id,"forged")).status).toBe(403);
      expect((await f.execute(p.id,jwt)).status).toBe(403);
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
      expect(f.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("rejects JWS for different proposal, commission, review, operator or unverified MFA",async()=>{
    const f=await fixture();
    try{
      const p=await (await f.propose()).json() as {id:string};
      for(const overrides of [
        {proposalId:"other_proposal"},
        {commissionId:"other_commission"},
        {reviewId:"other_review"},
        {operatorSubject:"different_operator"},
        {approverSubject:"different_approver"},
        {mfa:"not_verified"},
        {mfaAt:Math.floor(Date.now()/1000)-9000},
        {decision:"rejected"}
      ]){
        const jwt=await f.approvalJwt(p.id,overrides);
        expect((await f.approve(p.id,jwt)).status).toBe(403);
      }
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
    }finally{f.close();}
  });

  it("rejects changed request key, signed approval replay substitution, direct SQL bypass and expired pending",async()=>{
    const f=await fixture();
    try{
      const p=await (await f.propose()).json() as {id:string};
      const retry=await f.propose();
      expect(retry.status).toBe(202);
      expect(await retry.json()).toMatchObject({id:p.id,replayed:true});
      const conflict=await handleIsolatedOperatorRequest(post("redrive-proposals",
        {...f.input,reviewId:"different_review"},f.operatorHeader),f.env);
      expect(conflict.status).toBe(409);
      const jwt=await f.approvalJwt(p.id);
      expect((await f.approve(p.id,jwt)).status).toBe(200);
      expect((await f.approve(p.id,jwt)).status).toBe(200);
      expect(await (await f.approve(p.id,jwt)).json()).toMatchObject({replayed:true});
      const different=await f.approvalJwt(p.id,{jti:"another-jws"});
      expect((await f.approve(p.id,different)).status).toBe(409);
      expect((await f.execute(p.id,different)).status).toBe(403);
      expect(()=>f.sqlite.prepare("UPDATE processing_async_redrive_requests SET commission_id='x'").run())
        .toThrow(/ASYNC_REDRIVE_IMMUTABLE/);
      expect(()=>f.sqlite.prepare("DELETE FROM processing_async_redrive_approvals").run())
        .toThrow(/ASYNC_REDRIVE_APPROVAL_IMMUTABLE/);
      const approved=await f.execute(p.id,jwt);
      expect(approved.status).toBe(200);
      expect(f.send).toHaveBeenCalledOnce();
    }finally{f.close();}
  });

  it("rejects stale proposal with no approval/Queue, and synthetic legacy direct redrive is off by default",async()=>{
    const f=await fixture();
    try{
      const p=await (await f.propose()).json() as {id:string};
      expect((await handleIsolatedOperatorRequest(post(
        "redrives",f.input,f.operatorHeader),f.env)).status).toBe(404);
      f.sqlite.prepare("UPDATE processing_async_redrive_requests SET expires_at=requested_at+1 WHERE id=?").run(p.id);
      const clock=vi.spyOn(Date,"now").mockReturnValue(Date.now()+3000);
      const jwt=await f.approvalJwt(p.id);
      expect((await f.approve(p.id,jwt)).status).toBe(403);
      clock.mockRestore();
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
      expect(f.send).not.toHaveBeenCalled();
    }finally{vi.restoreAllMocks();f.close();}
  });

  it("denies cross-commission, nonexistent or unendorsed proposals before any approval",async()=>{
    const f=await fixture();
    try{
      for(const scope of [
        {...f.input,commissionId:"c_other"},
        {...f.input,reviewId:"nonexistent_review"}
      ]){
        const r=await handleIsolatedOperatorRequest(
          post("redrive-proposals",scope,f.operatorHeader),f.env
        );
        expect(r.status).toBe(409);
      }
      expect((await handleIsolatedOperatorRequest(post("redrive-proposals",{
        ...f.input,approvalRef:"INC_20261119_777"
      },f.operatorHeader),f.env)).status).toBe(403);
      expect(f.counts()).toEqual({proposals:{n:0},approvals:{n:0},sends:{n:0}});
    }finally{f.close();}
  });

  it("one ambiguous Queue response remains uncertain with durable audit and can never re-enqueue",async()=>{
    const f=await fixture();
    try{
      const p=await (await f.propose()).json() as {id:string};
      const jws=await f.approvalJwt(p.id);
      expect((await f.approve(p.id,jws)).status).toBe(200);
      f.send.mockRejectedValueOnce(new Error("Queue may have accepted before a disconnected response"));
      const first=await f.execute(p.id,jws);
      expect(first.status).toBe(202);
      const result=await first.json() as Record<string,unknown>;
      expect(result).toMatchObject({state:"uncertain",replayed:false});
      const replay=await f.execute(p.id,jws);
      expect(replay.status).toBe(202);
      expect(await replay.json()).toEqual({...result,replayed:true});
      expect(f.send).toHaveBeenCalledTimes(1);
      expect(f.counts().sends).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT state FROM processing_manual_redrives").get())
        .toMatchObject({state:"uncertain"});
    }finally{f.close();}
  });

  it("failed D1 decision batch rolls back approval atomically and a valid retry can finish",async()=>{
    const f=await fixture();
    try{
      const p=await (await f.propose()).json() as {id:string};
      const jwt=await f.approvalJwt(p.id);
      const broken={
        prepare:f.db.prepare.bind(f.db),
        batch:async()=>{throw new Error("D1 unavailable during approval");}
      } as unknown as D1Database;
      const failed=await handleIsolatedOperatorRequest(post("redrive-approvals",
        {requestId:p.id},{
          ...f.approverHeader,"X-Folio-Redrive-Approval-Jws":jwt
        }),{...f.env,db:broken});
      expect(failed.status).toBe(409);
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
      expect(f.sqlite.prepare("SELECT status FROM processing_async_redrive_requests").get())
        .toMatchObject({status:"pending"});
      expect((await f.approve(p.id,jwt)).status).toBe(200);
      expect(f.counts().approvals).toEqual({n:1});
    }finally{f.close();}
  });

  it("competing different signed approvals cannot overwrite each other and a forged D1 update cannot approve",async()=>{
    const f=await fixture();
    try{
      const p=await (await f.propose()).json() as {id:string};
      const one=await f.approvalJwt(p.id);
      const other=await f.approvalJwt(p.id,{jti:"different_signed_approval"});
      expect(()=>f.sqlite.prepare(`
        UPDATE processing_async_redrive_requests
        SET status='approved',approver_subject=?,
          approval_sha256=?,approval_key_thumbprint=?,approved_at=unixepoch()
        WHERE id=?
      `).run(APPROVER,"a".repeat(64),"A".repeat(43),p.id))
        .toThrow(/ASYNC_REDRIVE_TRANSITION/);
      const replies=await Promise.all([f.approve(p.id,one),f.approve(p.id,other)]);
      expect(replies.map(x=>x.status).sort()).toEqual([200,409]);
      expect(f.counts().approvals).toEqual({n:1});
      expect(f.counts().sends).toEqual({n:0});
      const approvedHash=f.sqlite.prepare("SELECT approval_sha256 AS digest FROM processing_async_redrive_requests").get() as {digest:string};
      expect(approvedHash.digest).toMatch(/^[0-9a-f]{64}$/);
    }finally{f.close();}
  });

  it.each(["operator","approver"] as const)(
    "revoked %s cannot authorize or replay an asynchronous redrive approval",
    async(role)=>{
      const f=await fixture();
      try{
        const id=(await (await f.propose()).json() as {id:string}).id;
        const jws=await f.approvalJwt(id);
        insertSyntheticAuditedRevocation(f,"operator",
          role==="operator"?f.signed.config.configuredOperatorSubject!:APPROVER);
        expect((await f.approve(id,jws)).status).toBe(403);
        if(role==="operator"){
          expect(()=>f.sqlite.prepare(`
            INSERT INTO processing_async_redrive_approvals(
              request_id,operator_subject,approver_subject,
              approval_sha256,approval_key_thumbprint
            ) VALUES(?,?,?,?,?)
          `).run(id,f.signed.config.configuredOperatorSubject!,APPROVER,
            "a".repeat(64),"A".repeat(43)))
            .toThrow(/ASYNC_REDRIVE_OPERATOR_REVOKED/);
        }
        expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
        expect(f.send).not.toHaveBeenCalled();
      }finally{f.close();}
    }
  );

  it("D1 rejects operator revocation racing between redrive approval preflight and batch",async()=>{
    const f=await fixture();
    try{
      const id=(await (await f.propose()).json() as {id:string}).id;
      const jws=await f.approvalJwt(id);
      const concurrent={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          insertSyntheticAuditedRevocation(f,"operator",f.signed.config.configuredOperatorSubject!);
          return f.db.batch(statements);
        }
      } as unknown as D1Database;
      const result=await handleIsolatedOperatorRequest(post("redrive-approvals",
        {requestId:id},{...f.approverHeader,"X-Folio-Redrive-Approval-Jws":jws}
      ),{...f.env,db:concurrent});
      expect(result.status).toBe(409);
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:0},sends:{n:0}});
      expect(f.sqlite.prepare("SELECT status FROM processing_async_redrive_requests").get())
        .toMatchObject({status:"pending"});
      expect(f.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("does not return an approved replay after the operator loses authority",async()=>{
    const f=await fixture();
    try{
      const id=(await (await f.propose()).json() as {id:string}).id;
      const jws=await f.approvalJwt(id);
      expect((await f.approve(id,jws)).status).toBe(200);
      insertSyntheticAuditedRevocation(f,"operator",f.signed.config.configuredOperatorSubject!);
      expect((await f.approve(id,jws)).status).toBe(403);
      expect((await f.execute(id,jws)).status).toBe(403);
      expect(f.counts()).toEqual({proposals:{n:1},approvals:{n:1},sends:{n:0}});
    }finally{f.close();}
  });

  it("revoking the independent approver after approval blocks the final Queue action",async()=>{
    const f=await fixture();
    try{
      const proposal=await (await f.propose()).json() as {id:string};
      const jws=await f.approvalJwt(proposal.id);
      expect((await f.approve(proposal.id,jws)).status).toBe(200);
      insertSyntheticAuditedRevocation(f,"operator",APPROVER);
      expect((await f.execute(proposal.id,jws)).status).toBe(403);
      expect(f.counts().sends).toEqual({n:0});
      expect(f.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("revocation after durable reservation halts the one-shot send and preserves its audit",async()=>{
    const f=await fixture();
    try{
      const proposal=await (await f.propose()).json() as {id:string};
      const jws=await f.approvalJwt(proposal.id);
      expect((await f.approve(proposal.id,jws)).status).toBe(200);
      let batches=0;
      const wrapped={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          const result=await f.db.batch(statements);
          if(++batches===1){
            insertSyntheticAuditedRevocation(f,"operator",APPROVER);
          }
          return result;
        }
      } as unknown as D1Database;
      const r=await f.execute(proposal.id,jws,{
        config:{...f.env,db:wrapped},
        headers:f.operatorHeader,
        releaseJwt:f.signed.evidence.releaseJwt
      });
      expect(r.status).toBe(200);
      expect(await r.json()).toMatchObject({state:"halted",replayed:false});
      expect(f.send).not.toHaveBeenCalled();
      expect(f.counts().sends).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT state FROM processing_manual_redrives").get())
        .toMatchObject({state:"halted"});
    }finally{f.close();}
  });

  it("failed D1 reservation leaves no Queue message and retry can claim it once",async()=>{
    const f=await fixture();
    try{
      const p=await (await f.propose()).json() as {id:string};
      const jwt=await f.approvalJwt(p.id);
      expect((await f.approve(p.id,jwt)).status).toBe(200);
      const broken={
        prepare:f.db.prepare.bind(f.db),
        batch:async()=>{throw new Error("Simulated D1 claim transaction outage");}
      } as unknown as D1Database;
      const failed=await f.execute(p.id,jwt,{
        config:{...f.env,db:broken},headers:f.operatorHeader,
        releaseJwt:f.signed.evidence.releaseJwt
      });
      expect(failed.status).toBe(409);
      expect(f.send).not.toHaveBeenCalled();
      expect(f.counts().sends).toEqual({n:0});
      expect((await f.execute(p.id,jwt)).status).toBe(200);
      expect(f.send).toHaveBeenCalledOnce();
    }finally{f.close();}
  });

  it("blocks an image revoked after approval but before execution, without sending",async()=>{
    const f=await fixture();
    try{
      const p=await (await f.propose()).json() as {id:string};
      const jwt=await f.approvalJwt(p.id);
      expect((await f.approve(p.id,jwt)).status).toBe(200);
      insertSyntheticAuditedRevocation(f,"image",f.signed.config.requiredImageDigest!);
      expect((await f.execute(p.id,jwt)).status).toBe(403);
      expect(f.counts().sends).toEqual({n:0});
      expect(f.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });
});
