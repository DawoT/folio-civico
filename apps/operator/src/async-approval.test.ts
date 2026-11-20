import {afterEach,describe,expect,it,vi} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {revocationFixture} from "../../../packages/auth/src/revocation-fixture.test-helper";
import {handleIsolatedOperatorRequest,type IsolatedOperatorConfig} from "./isolated-host";

afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});
const BASE="https://operator.local/internal/operations/";
function call(route:string,body:unknown,token?:string,approval?:string) {
  return new Request(BASE+route,{method:"POST",headers:{
    "Content-Type":"application/json",
    ...(token?{"Cf-Access-Jwt-Assertion":token}:{}),
    ...(approval?{"X-Folio-Incident-Approval-Jws":approval}:{})
  },body:JSON.stringify(body)});
}
function actorJwt(f:Awaited<ReturnType<typeof revocationFixture>>) {
  return f.evidence.actorAccessRequest.headers.get("Cf-Access-Jwt-Assertion")!;
}
function approverJwt(f:Awaited<ReturnType<typeof revocationFixture>>) {
  return f.evidence.approverAccessRequest.headers.get("Cf-Access-Jwt-Assertion")!;
}
function cfg(f:Awaited<ReturnType<typeof revocationFixture>>,db:D1Database):IsolatedOperatorConfig {
  return {mode:"synthetic-offline-only",db,revocationTrust:f.config};
}

function revokeOperator(db:ReturnType<typeof makeD1>,subject:string):void {
  const key=`revoke_access_${subject}`;
  db.sqlite.prepare(`
    INSERT INTO processing_redrive_revocation_actions(
      actor_subject,request_key,kind,target,incident_ref,approver_subject,
      target_sha256,reason_sha256,approval_sha256,approval_key_thumbprint,payload_sha256
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
  `).run("audit_actor",key,"operator",subject,"INC_REVOKE_ACCESS_001",
    "audit_approver","a".repeat(64),"b".repeat(64),"c".repeat(64),
    "A".repeat(43),"d".repeat(64));
  db.sqlite.prepare(`
    INSERT INTO processing_redrive_revocations(kind,target,incident_ref)
    VALUES('operator',?,'INC_REVOKE_ACCESS_001')
  `).run(subject);
}

describe("R2.10: independent, asynchronous incident revocation approval",()=>{
  it("persists a gated institutional version atomically and cannot downgrade or replay against a newer version",async()=>{
    const d=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,d.db);
      let revision=12;
      const reader={readCurrentEvidence:async(query:Record<string,unknown>)=>{
        const now=Math.floor(Date.now()/1000);
        return {...query,revision,status:"open",decision:"approved",
          reviewerSubject:query.approverSubject,
          checkedAt:now,reviewedAt:now-5,mfaVerifiedAt:now-10,validUntil:now+60};
      }};
      conf.institutionalGate={reader};
      const req=call("revocation-proposals",f.scope,actorJwt(f));
      const proposal=await handleIsolatedOperatorRequest(req,conf);
      expect(proposal.status).toBe(202);
      const id=(await proposal.json() as {id:string}).id;
      expect(d.sqlite.prepare(`
        SELECT institutional_gate_required AS required
        FROM processing_async_revocation_requests WHERE id=?
      `).get(id)).toMatchObject({required:1});
      conf.institutionalGate=undefined;
      const approve=()=>handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
      ),conf);
      expect((await approve()).status).toBe(503);
      expect(d.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
      conf.institutionalGate={reader};
      expect((await approve()).status).toBe(200);
      const evidence=d.sqlite.prepare(`
        SELECT purpose,case_revision AS revision,scope_sha256 AS scope,
          approval_sha256 AS digest,checked_at AS checked
        FROM processing_institutional_approval_evidence WHERE request_id=?
      `).get(id) as {purpose:string;revision:number;scope:string;digest:string;checked:number};
      expect(evidence).toMatchObject({
        purpose:"revocation",revision:12,scope:expect.stringMatching(/^[0-9a-f]{64}$/),
        digest:expect.stringMatching(/^[0-9a-f]{64}$/)
      });
      expect(JSON.stringify(evidence)).not.toContain(f.evidence.approvalJwt);
      conf.institutionalGate=undefined;
      expect((await approve()).status).toBe(503);
      revision=13;
      conf.institutionalGate={reader};
      expect((await approve()).status).toBe(403);
      revision=12;
      expect((await approve()).status).toBe(200);
      expect(d.sqlite.prepare("SELECT count(*) AS n FROM processing_institutional_approval_evidence").get())
        .toMatchObject({n:1});
    }finally{d.close();}
  });

  it("rolls back the institutional receipt with the entire failed decision batch",async()=>{
    const d=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,d.db);
      conf.institutionalGate={reader:{readCurrentEvidence:async(query:Record<string,unknown>)=>{
        const now=Math.floor(Date.now()/1000);
        return {...query,revision:4,status:"open",decision:"approved",
          reviewerSubject:query.approverSubject,
          checkedAt:now,reviewedAt:now-3,mfaVerifiedAt:now-6,validUntil:now+60};
      }}};
      const id=(await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),conf)).json() as {id:string}).id;
      const failing={
        prepare:d.db.prepare.bind(d.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>
          d.db.batch([...statements,d.db.prepare("INSERT INTO missing_table VALUES(1)")])
      } as unknown as D1Database;
      const result=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
      ),{...conf,db:failing});
      expect(result.status).toBe(409);
      for(const table of [
        "processing_institutional_approval_evidence",
        "processing_redrive_revocations",
        "processing_redrive_revocation_actions"
      ]){
        expect(d.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get())
          .toMatchObject({n:0});
      }
      expect(d.sqlite.prepare("SELECT status FROM processing_async_revocation_requests").get())
        .toMatchObject({status:"pending"});
    }finally{d.close();}
  });

  it("can require fresh independent institutional evidence before approval and on replay",async()=>{
    const d=makeD1();
    try{
      const f=await revocationFixture();
      const config=cfg(f,d.db);
      const id=(await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),config
      )).json() as {id:string}).id;
      config.institutionalGate={};
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
      ),config)).status).toBe(503);
      expect(d.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
      let status="open";
      const source=vi.fn(async(query:Record<string,unknown>)=>{
        const t=Math.floor(Date.now()/1000);
        return {...query,status,revision:5,decision:"approved",
          reviewerSubject:query.approverSubject,
          checkedAt:t,reviewedAt:t-5,mfaVerifiedAt:t-15,validUntil:t+60};
      });
      config.institutionalGate={reader:{readCurrentEvidence:source}};
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
      ),config)).status).toBe(200);
      expect(source).toHaveBeenCalledWith(expect.objectContaining({
        purpose:"revocation",caseRef:f.scope.incidentRef,requestId:id,
        actorSubject:f.actor,approverSubject:f.approver,
        approvalDigest:expect.stringMatching(/^[a-f0-9]{64}$/),
        scopeDigest:expect.stringMatching(/^[a-f0-9]{64}$/)
      }));
      status="closed";
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
      ),config)).status).toBe(403);
      expect(d.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
    }finally{d.close();}
  });

  it("stores an authenticated actor request without the approver JWT; a separate later request finalizes without actor JWT",async()=>{
    const fdb=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,fdb.db);
      const proposed=await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),conf);
      expect(proposed.status).toBe(202);
      const p=await proposed.json() as {id:string;status:string;replayed:boolean};
      expect(p).toMatchObject({status:"pending",replayed:false});
      expect(p.id).toMatch(/^[0-9a-f-]{36}$/);
      expect(fdb.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
      const approved=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:p.id},approverJwt(f),f.evidence.approvalJwt
      ),conf);
      expect(approved.status).toBe(200);
      expect(await approved.json()).toEqual({status:"approved",replayed:false});
      expect(fdb.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
      expect(fdb.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocation_actions").get())
        .toMatchObject({n:1});
      const row=fdb.sqlite.prepare("SELECT status,actor_subject AS actor,approver_subject AS approver FROM processing_async_revocation_requests").get();
      expect(row).toMatchObject({status:"approved",actor:f.actor,approver:f.approver});
      const persisted=JSON.stringify(fdb.sqlite.prepare("SELECT * FROM processing_async_revocation_requests").all());
      expect(persisted).not.toContain(f.scope.reason);
      expect(persisted).not.toContain(f.evidence.approvalJwt);
      expect(persisted).not.toContain(actorJwt(f));
      expect(persisted).not.toContain(approverJwt(f));
    }finally{fdb.close();}
  });

  it.each(["actor","approver"] as const)(
    "withdrawn %s authority denies a previously valid pending revocation before any D1 journal",
    async(role)=>{
      const db=makeD1();
      try{
        const f=await revocationFixture();
        const config=cfg(f,db.db);
        const proposal=await handleIsolatedOperatorRequest(call(
          "revocation-proposals",f.scope,actorJwt(f)),config);
        const id=(await proposal.json() as {id:string}).id;
        revokeOperator(db,role==="actor"?f.actor:f.approver);
        const result=await handleIsolatedOperatorRequest(call(
          "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
        ),config);
        expect(result.status).toBe(403);
        expect(db.sqlite.prepare("SELECT status FROM processing_async_revocation_requests WHERE id=?").get(id))
          .toMatchObject({status:"pending"});
        expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocation_actions").get())
          .toMatchObject({n:1});
      }finally{db.close();}
    }
  );

  it("rejects a new or replayed proposal after its actor loses authority",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const config=cfg(f,db.db);
      const first=await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),config);
      expect(first.status).toBe(202);
      revokeOperator(db,f.actor);
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),config)).status).toBe(403);
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-proposals",{...f.scope,requestKey:"revocation_new_after_loss"},actorJwt(f)),config)).status).toBe(403);
      expect(()=>db.sqlite.prepare(`
        INSERT INTO processing_async_revocation_requests(
          id,actor_subject,request_key,kind,target,incident_ref,
          target_sha256,reason_sha256,payload_sha256,expires_at
        ) VALUES(?,?,?,?,?,?,?,?,?,unixepoch()+3600)
      `).run(crypto.randomUUID(),f.actor,"revoked_sql_direct_001",f.scope.kind,
        f.scope.target,f.scope.incidentRef,"a".repeat(64),"b".repeat(64),"c".repeat(64)))
        .toThrow(/ASYNC_REVOCATION_ACTOR_REVOKED/);
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_async_revocation_requests").get())
        .toMatchObject({n:1});
    }finally{db.close();}
  });

  it("D1 aborts an incident approval if authority is withdrawn after preflight but before the atomic batch",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const config=cfg(f,db.db);
      const id=(await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),config)).json() as {id:string}).id;
      const concurrent={
        prepare:db.db.prepare.bind(db.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          revokeOperator(db,f.actor);
          return db.db.batch(statements);
        }
      } as unknown as D1Database;
      const result=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
      ),{...config,db:concurrent});
      expect(result.status).toBe(409);
      expect(db.sqlite.prepare("SELECT status FROM processing_async_revocation_requests WHERE id=?").get(id))
        .toMatchObject({status:"pending"});
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocation_actions").get())
        .toMatchObject({n:1});
    }finally{db.close();}
  });

  it("previously approved incident cannot be reapproved after actor authority is revoked",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const config=cfg(f,db.db);
      const id=(await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),config)).json() as {id:string}).id;
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt),config)).status).toBe(200);
      revokeOperator(db,f.actor);
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt),config)).status).toBe(403);
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get()).toMatchObject({n:2});
    }finally{db.close();}
  });

  it("fails closed without first actor JWT, with self-approval, wrong approver or unsigned second stage",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,db.db);
      expect((await handleIsolatedOperatorRequest(call("revocation-proposals",f.scope),conf)).status).toBe(403);
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,approverJwt(f)),conf)).status).toBe(403);
      const p=await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),conf)).json() as {id:string};
      for(const [jwt,jws] of [
        [actorJwt(f),f.evidence.approvalJwt],
        [approverJwt(f),undefined],
        [approverJwt(f),"malformed"],
        [await f.signAccess("third-person"),f.evidence.approvalJwt]
      ]){
        const r=await handleIsolatedOperatorRequest(call(
          "revocation-approvals",{requestId:p.id},jwt,jws),conf);
        expect(r.status).toBe(403);
      }
      expect(db.sqlite.prepare("SELECT status FROM processing_async_revocation_requests").get())
        .toMatchObject({status:"pending"});
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
    }finally{db.close();}
  });

  it("is idempotent in both stages; rejects altered proposal and signed approval for another incident or target",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,db.db);
      const proposal=call("revocation-proposals",f.scope,actorJwt(f));
      const p=await (await handleIsolatedOperatorRequest(proposal,conf)).json() as {id:string};
      const repeated=await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),conf);
      expect(repeated.status).toBe(202);
      expect(await repeated.json()).toEqual({id:p.id,status:"pending",replayed:true});
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-proposals",{...f.scope,reason:"Different signed incident reason demonstrating payload tampering."},actorJwt(f)),conf)).status).toBe(409);
      const altered=await f.signApproval({targetHash:"a".repeat(64)});
      expect((await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:p.id},approverJwt(f),altered),conf)).status).toBe(403);
      const a=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:p.id},approverJwt(f),f.evidence.approvalJwt),conf);
      expect(a.status).toBe(200);
      const replay=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:p.id},approverJwt(f),f.evidence.approvalJwt),conf);
      expect(replay.status).toBe(200);
      expect(await replay.json()).toEqual({status:"approved",replayed:true});
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
    }finally{db.close();}
  });

  it("rolls back if an incident is stale or the approval is replaced; never stores a partial audit journal",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,db.db);
      const p=await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),conf)).json() as {id:string};
      db.sqlite.prepare("UPDATE processing_async_revocation_requests SET expires_at=requested_at+1 WHERE id=?")
        .run(p.id);
      const clock=vi.spyOn(Date,"now").mockReturnValue(Date.now()+3000);
      const r=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:p.id},approverJwt(f),f.evidence.approvalJwt
      ),conf);
      clock.mockRestore();
      expect(r.status).toBe(403);
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get()).toMatchObject({n:0});
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocation_actions").get()).toMatchObject({n:0});
    }finally{db.close();}
  });

  it("allows independent proposals for the same target; only one distinct signed approval can win",async()=>{
    const db=makeD1();
    try{
      const first=await revocationFixture({requestKey:"incident_competing_first"});
      const second=await revocationFixture({requestKey:"incident_competing_second"});
      const config=cfg(first,db.db);
      const p1=await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",first.scope,actorJwt(first)),config)).json() as {id:string};
      const p2=await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",second.scope,actorJwt(second)),config)).json() as {id:string};
      expect(p1.id).not.toBe(p2.id);
      const r1=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:p1.id},
        approverJwt(first),first.evidence.approvalJwt),config);
      expect(r1.status).toBe(200);
      const r2=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:p2.id},
        approverJwt(second),second.evidence.approvalJwt),config);
      expect(r2.status).toBe(409);
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocation_actions").get())
        .toMatchObject({n:1});
      expect(db.sqlite.prepare("SELECT status FROM processing_async_revocation_requests WHERE id=?").get(p2.id))
        .toMatchObject({status:"pending"});
    }finally{db.close();}
  });

  it("D1 refuses forged approvals, scope mutations and deletion without the signed atomic journal",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,db.db);
      const id=(await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),conf)).json() as {id:string}).id;
      expect(()=>db.sqlite.prepare(`
        UPDATE processing_async_revocation_requests
        SET status='approved',approver_subject=?,approval_sha256=?,
            approval_key_thumbprint=?,decided_at=unixepoch()
        WHERE id=?
      `).run(f.approver,"a".repeat(64),"A".repeat(43),id))
        .toThrow(/ASYNC_REVOCATION_TRANSITION/);
      expect(()=>db.sqlite.prepare("UPDATE processing_async_revocation_requests SET target=? WHERE id=?")
        .run("sha256:"+"f".repeat(64),id)).toThrow(/ASYNC_REVOCATION_IMMUTABLE/);
      expect(()=>db.sqlite.prepare("DELETE FROM processing_async_revocation_requests WHERE id=?")
        .run(id)).toThrow(/ASYNC_REVOCATION_IMMUTABLE/);
      expect(()=>db.sqlite.prepare(
        "UPDATE processing_async_revocation_requests SET expires_at=expires_at+60 WHERE id=?"
      ).run(id)).toThrow(/ASYNC_REVOCATION_TRANSITION|CHECK constraint failed/);
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
    }finally{db.close();}
  });

  it("rejects stale/forged incident decisions and does not require either principal to handle the other's JWT",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,db.db);
      const id=(await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),conf)).json() as {id:string}).id;
      for(const decision of [
        await f.signApproval({reasonHash:"1".repeat(64)}),
        await f.signApproval({incidentRef:"INC_OTHER_2026"}),
        await f.signApproval({actorSubject:f.approver}),
        await f.signApproval({decision:"rejected"}),
        await f.signApproval({mfaAt:Math.floor(Date.now()/1000)-7200}),
        await f.signApproval({}, {wrongKey:true})
      ]) {
        const denied=await handleIsolatedOperatorRequest(call(
          "revocation-approvals",{requestId:id},approverJwt(f),decision),conf);
        expect(denied.status).toBe(403);
      }
      const fakeProposal=call("revocation-proposals",f.scope,actorJwt(f));
      fakeProposal.headers.set("X-Folio-Approver-Access-Jwt",approverJwt(f));
      expect((await handleIsolatedOperatorRequest(fakeProposal,conf)).status).toBe(403);
      const fakeApproval=call("revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt);
      fakeApproval.headers.set("X-Folio-Approver-Access-Jwt",actorJwt(f));
      expect((await handleIsolatedOperatorRequest(fakeApproval,conf)).status).toBe(403);
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
    }finally{db.close();}
  });

  it("an interrupted atomic approval leaves request pending and no partial journal, then may be approved once",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const config=cfg(f,db.db);
      const id=(await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),config)).json() as {id:string}).id;
      const unavailable={
        prepare:db.db.prepare.bind(db.db),
        batch:async()=>{throw new Error("D1 batch interrupted after validating request");}
      } as unknown as D1Database;
      const denied=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
      ),{...config,db:unavailable});
      expect(denied.status).toBe(409);
      expect(await denied.text()).not.toContain("D1 batch interrupted");
      expect(db.sqlite.prepare("SELECT status FROM processing_async_revocation_requests WHERE id=?").get(id))
        .toMatchObject({status:"pending"});
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocation_actions").get())
        .toMatchObject({n:0});
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
      const eventual=await handleIsolatedOperatorRequest(call(
        "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt
      ),config);
      expect(eventual.status).toBe(200);
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
    }finally{db.close();}
  });

  it("concurrent approvals with a different signed JWS cannot overwrite the first approver journal",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const config=cfg(f,db.db);
      const id=(await (await handleIsolatedOperatorRequest(call(
        "revocation-proposals",f.scope,actorJwt(f)),config)).json() as {id:string}).id;
      const distinctJws=await f.signApproval({jti:"distinct-signed-incident-decision"});
      const results=await Promise.all([
        handleIsolatedOperatorRequest(call(
          "revocation-approvals",{requestId:id},approverJwt(f),f.evidence.approvalJwt),config),
        handleIsolatedOperatorRequest(call(
          "revocation-approvals",{requestId:id},approverJwt(f),distinctJws),config)
      ]);
      expect(results.map(r=>r.status).sort()).toEqual([200,409]);
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocation_actions").get())
        .toMatchObject({n:1});
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
      expect(db.sqlite.prepare("SELECT status FROM processing_async_revocation_requests WHERE id=?").get(id))
        .toMatchObject({status:"approved"});
    }finally{db.close();}
  });

  it("rejects wrong origin, injected extra fields and browser Origin; default disabled before parsing",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const conf=cfg(f,db.db);
      const request=call("revocation-proposals",f.scope,actorJwt(f));
      const disabled=await handleIsolatedOperatorRequest(request,{db:db.db,revocationTrust:f.config});
      expect(disabled.status).toBe(503);
      expect((await handleIsolatedOperatorRequest(call(
        "revocations",f.scope,actorJwt(f)),conf)).status).toBe(404);
      for(const r of [
        new Request(BASE+"revocation-proposals",{method:"GET"}),
        new Request("https://evil.example/internal/operations/revocation-proposals",{
          method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(f.scope)
        }),
        call("revocation-proposals",{...f.scope,approverSubject:f.approver},actorJwt(f)),
        call("revocation-approvals",{requestId:"unknown",actorSubject:f.actor},approverJwt(f),f.evidence.approvalJwt),
        new Request(BASE+"revocation-proposals",{
          method:"POST",
          headers:{"Content-Type":"application/json","Origin":"https://evil.example",
            "Cf-Access-Jwt-Assertion":actorJwt(f)},
          body:JSON.stringify(f.scope)
        })
      ]){
        const result=await handleIsolatedOperatorRequest(r,conf);
        expect([400,403,404,405]).toContain(result.status);
      }
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_async_revocation_requests").get())
        .toMatchObject({n:0});
    }finally{db.close();}
  });
});
