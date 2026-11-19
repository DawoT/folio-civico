import {afterEach,describe,it,expect,vi} from "vitest";
import type {VerifiedRedriveAuthorization,RevocationKind} from "@folio/auth";
import {revocationFixture} from "../../auth/src/revocation-fixture.test-helper";
import {registerRedriveRevocation} from "./revocation-registration";
import {syntheticOperatorAuthorization} from "../../../packages/auth/src/signed-fixture.test-helper";
afterEach(()=>vi.unstubAllGlobals());
import {makeD1} from "../../../tests/helpers/d1";
import {persistDocumentUpload} from "./documents";
import {openRecoveryReview,decideRecoveryReview} from "./recovery-review";
import {executeOneShotManualRedrive,ManualRedriveAccessError,ManualRedriveConflictError,ManualRedriveInputError} from "./manual-redrive";
import {processBatch} from "../../../apps/processor/src/consumer";

const SHA="a".repeat(64);
async function fixture(){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
    ('c_a','Commission synthetic A','active'),('c_b','Commission synthetic B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
    ('c_a','president','president',1),('c_a','reviewer','member',1),
    ('c_a','observer','observer',1),('c_b','outside','president',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES
    ('batch_a','c_a','One'),('batch_b','c_b','Two');
  `);
  for(const [version,commission,subject,batch] of [
    ["version_a","c_a","president","batch_a"],
    ["version_b","c_a","president","batch_a"],
    ["version_other","c_b","outside","batch_b"]
  ] as const){
    await persistDocumentUpload(f.db,{
      commissionId:commission,batchId:batch,subject,
      documentId:"doc_"+version,versionId:version,
      sha256:SHA,r2Key:"quarantine/"+version+".pdf",filename:"secret_"+version+".pdf",
      idempotencyKey:"upload_"+version+"_key"
    });
  }
  f.sqlite.exec(`
    UPDATE document_processing_outbox SET state='sent',attempts=10,last_sent_at='2026-11-19T12:00:00.000Z'
    WHERE document_version_id IN ('version_a','version_other');
  `);
  async function endorsed(){
    const opened=await openRecoveryReview(f.db,{
      commissionId:"c_a",versionId:"version_a",sourceSha256:SHA,
      actorSubject:"president",incidentRef:"INC_20261119_001",
      requestKey:"recovery_open_0001"
    });
    await decideRecoveryReview(f.db,{
      commissionId:"c_a",reviewId:opened.id,actorSubject:"reviewer",
      decision:"endorse",requestKey:"recovery_decide_0001",
      rationale:"Document verified only for independent operator consideration."
    });
    const signed=await syntheticOperatorAuthorization({reviewId:opened.id});
    env.authorization=await signed.verify();
    env.requiredInspectorImageDigest=signed.config.requiredImageDigest;
    return opened.id;
  }
  const sent:Array<unknown>=[];
  const queue={send:vi.fn(async(message:unknown)=>{sent.push(message);})};
  const env:{DB:D1Database;QUEUE:typeof queue;
    authorization?:VerifiedRedriveAuthorization;requiredInspectorImageDigest?:string}={
    DB:f.db,QUEUE:queue
  };
  const input=(reviewId:string,overrides:Record<string,unknown>={})=>({
    commissionId:"c_a",reviewId,
    operatorSubject:"operator_authorized_001",
    requestKey:"operator_redrive_0001",operatorApprovalRef:"OPR_20261119_001",
    ...overrides
  });
  const row=()=>f.sqlite.prepare("SELECT state,attempts,last_sent_at AS lastSentAt FROM document_processing_outbox WHERE document_version_id='version_a'").get();
  const attempts=()=>f.sqlite.prepare("SELECT state,operator_subject AS operator,request_key AS requestKey,authorization_sha256 AS authorizationDigest FROM processing_manual_redrives").all();
  return {...f,env,input,queue,sent,endorse:endorsed,row,attempts};
}

async function registerFixtureRevocation(
  f:Awaited<ReturnType<typeof fixture>>,kind:RevocationKind,
  target:string,incidentSuffix:string
):Promise<void>{
  const approval=await revocationFixture({
    kind,target,
    incidentRef:"INC_REVOKE_20261119_"+incidentSuffix,
    requestKey:"revocation_fixture_"+kind+"_"+incidentSuffix,
    reason:"Independent synthetic incident approval for private denylist tests."
  });
  const proof=await approval.verify();
  await registerRedriveRevocation(f.db,approval.scope,proof);
}

describe("R2.5 · one-shot manual redrive, no active API/Cloudflare bindings",()=>{
  it("requires independent allowlisted operator and trusted inspector release gate before any writes or enqueue",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      for(const envChange of [
        {authorization:undefined},
        {requiredInspectorImageDigest:"sha256:"+"0".repeat(64)},
        {requiredInspectorImageDigest:undefined},
        {authorization:{...f.env.authorization} as VerifiedRedriveAuthorization},
        {authorization:undefined,inspectorReleaseApproved:true,
          configuredOperatorSubject:"operator_authorized_001"}
      ]){
        await expect(executeOneShotManualRedrive({...f.env,...envChange},f.input(reviewId)))
          .rejects.toBeInstanceOf(ManualRedriveAccessError);
      }
      for(const operatorSubject of ["president","reviewer","observer","outside","random"]){
        await expect(executeOneShotManualRedrive(f.env,f.input(reviewId,{operatorSubject,
          requestKey:"operator_"+operatorSubject+"_0001"})))
          .rejects.toBeInstanceOf(ManualRedriveAccessError);
      }
      expect(f.attempts()).toHaveLength(0);
      expect(f.queue.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("sends exactly one Queue message after durable reservation; replay returns state without another send",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      const original=f.row();
      const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get() as {n:number};
      f.queue.send.mockImplementationOnce(async(body:unknown)=>{
        expect(f.attempts()).toMatchObject([{
          state:"reserved",operator:"operator_authorized_001",requestKey:"operator_redrive_0001"
        }]);
        f.sent.push(body);
      });
      const first=await executeOneShotManualRedrive(f.env,f.input(reviewId));
      expect(first).toMatchObject({state:"sent",replayed:false});
      expect(first.id).toMatch(/^[0-9a-f-]{36}$/);
      expect(f.sent).toEqual([{kind:"folio.process.pdf",versionId:"version_a",sourceSha256:SHA}]);
      const repeated=await executeOneShotManualRedrive(f.env,f.input(reviewId));
      expect(repeated).toEqual({...first,replayed:true});
      expect(f.queue.send).toHaveBeenCalledOnce();
      expect(f.row()).toEqual(original);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:before.n+2});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_manual_redrives").get()).toMatchObject({n:1});
      expect(JSON.stringify(first)).not.toContain("version_a");
      expect(JSON.stringify(first)).not.toContain(SHA);
      expect(JSON.stringify(f.attempts())).not.toContain("quarantine/");
    }finally{f.close();}
  });

  it("does not enqueue in overlapping requests, even when Queue is unresolved",async()=>{
    const f=await fixture();
    let release:()=>void=()=>{};
    try{
      const reviewId=await f.endorse();
      const busy=new Promise<void>(resolve=>{release=resolve;});
      let entered:()=>void=()=>{};
      const inside=new Promise<void>(resolve=>{entered=resolve;});
      f.queue.send.mockImplementationOnce(async(body:unknown)=>{
        f.sent.push(body);entered();await busy;
      });
      const first=executeOneShotManualRedrive(f.env,f.input(reviewId));
      await inside;
      const another=await executeOneShotManualRedrive(f.env,f.input(reviewId));
      expect(another).toMatchObject({state:"reserved",replayed:true});
      expect(f.queue.send).toHaveBeenCalledOnce();
      await expect(executeOneShotManualRedrive(f.env,f.input(reviewId,{
        requestKey:"another_request_key_001"
      }))).rejects.toBeInstanceOf(ManualRedriveAccessError);
      release();
      const final=await first;
      expect(final.state).toBe("sent");
      expect(f.sent).toHaveLength(1);
      expect(f.attempts()).toHaveLength(1);
      expect(f.attempts()[0]).toMatchObject({authorizationDigest:f.env.authorization!.attestationDigest});
    }finally{release();f.close();}
  });

  it("records uncertain delivery when Queue rejects; retries never send again and outbox remains exhausted",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      const original=f.row();
      f.queue.send.mockRejectedValueOnce(new Error("Ambiguous Queue response: maybe enqueued"));
      const attempt=await executeOneShotManualRedrive(f.env,f.input(reviewId));
      expect(attempt).toMatchObject({state:"uncertain",replayed:false});
      expect((await executeOneShotManualRedrive(f.env,f.input(reviewId))))
        .toEqual({...attempt,replayed:true});
      expect(f.queue.send).toHaveBeenCalledOnce();
      expect(f.row()).toEqual(original);
      expect(f.attempts()).toMatchObject([{state:"uncertain"}]);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events WHERE action LIKE 'processing.manual_redrive_%'").get())
        .toMatchObject({n:2});
    }finally{f.close();}
  });

  it("fails closed for stale endorsements, wrong commission, failed/rejected document and future forged IDs",async()=>{
    for(const mutation of [
      "UPDATE commissions SET status='closed' WHERE id='c_a'",
      "UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='president'",
      "UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='reviewer'",
      "UPDATE document_processing_outbox SET attempts=9 WHERE document_version_id='version_a'",
      "UPDATE document_versions SET extraction_status='needs_review' WHERE id='version_a'"
    ]){
      const f=await fixture();
      try{
        const reviewId=await f.endorse();
        f.sqlite.exec(mutation);
        await expect(executeOneShotManualRedrive(f.env,f.input(reviewId)))
          .rejects.toBeInstanceOf(ManualRedriveConflictError);
        expect(f.queue.send).not.toHaveBeenCalled();
        expect(f.attempts()).toHaveLength(0);
      }finally{f.close();}
    }
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      await expect(executeOneShotManualRedrive(f.env,f.input("absent")))
        .rejects.toBeInstanceOf(ManualRedriveAccessError);
      for(const overrides of [
        {commissionId:"c_b"},{reviewId:"another_review"},{operatorApprovalRef:"../../secret"},
        {operatorApprovalRef:"INC_20261119_001"},{requestKey:"bad"},
        {operatorSubject:"ab\nforged"}
      ]){
        await expect(executeOneShotManualRedrive(f.env,f.input(reviewId,overrides)))
          .rejects.toThrow();
      }
      expect(f.attempts()).toHaveLength(0);
    }finally{f.close();}
  });

  it("halts when institutional eligibility changes after reservation but before sending",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      let calls=0;
      const wrapped={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          const result=await f.db.batch(statements);
          calls++;
          if(calls===1){
            // A reviewer is revoked just after the durable claim, before
            // the second permission/state check.
            f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='reviewer'");
          }
          return result;
        }
      } as D1Database;
      const result=await executeOneShotManualRedrive({...f.env,DB:wrapped},f.input(reviewId));
      expect(result).toMatchObject({state:"halted",replayed:false});
      expect(f.queue.send).not.toHaveBeenCalled();
      expect(f.attempts()).toMatchObject([{state:"halted"}]);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE action LIKE 'processing.manual_redrive_%'").get())
        .toMatchObject({n:2});
      const replay=await executeOneShotManualRedrive({...f.env,DB:wrapped},f.input(reviewId));
      expect(replay).toEqual({...result,replayed:true});
      expect(f.queue.send).not.toHaveBeenCalled();
      expect(f.row()).toMatchObject({attempts:10});
    }finally{f.close();}
  });

  it("halts if the signed operation authorization expires after the D1 reservation",async()=>{
    const f=await fixture();
    let clock:ReturnType<typeof vi.spyOn>|undefined;
    try {
      const reviewId=await f.endorse();
      let batches=0;
      const wrapped={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          const result=await f.db.batch(statements);
          batches++;
          if(batches===1)clock=vi.spyOn(Date,"now")
            .mockReturnValue(f.env.authorization!.expiresAt+1000);
          return result;
        }
      } as D1Database;
      const result=await executeOneShotManualRedrive({...f.env,DB:wrapped},f.input(reviewId));
      expect(result.state).toBe("halted");
      expect(f.queue.send).not.toHaveBeenCalled();
      expect(f.attempts()).toMatchObject([{
        state:"halted",authorizationDigest:f.env.authorization!.attestationDigest
      }]);
      expect(f.row()).toMatchObject({attempts:10});
    }finally{clock?.mockRestore();f.close();}
  });

  it("never resends after an ambiguous crash during final D1 write, retaining a durable reservation",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      let calls=0;
      const wrapped={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          calls++;
          if(calls===2)throw new Error("Local D1 unavailable after Queue acceptance");
          return f.db.batch(statements);
        }
      } as D1Database;
      await expect(executeOneShotManualRedrive({...f.env,DB:wrapped},f.input(reviewId)))
        .rejects.toBeInstanceOf(ManualRedriveConflictError);
      expect(f.queue.send).toHaveBeenCalledOnce();
      expect(f.attempts()).toMatchObject([{state:"reserved"}]);
      const replay=await executeOneShotManualRedrive(f.env,f.input(reviewId));
      expect(replay).toMatchObject({state:"reserved",replayed:true});
      expect(f.queue.send).toHaveBeenCalledOnce();
      expect(f.row()).toMatchObject({attempts:10});
    }finally{f.close();}
  });

  it("prevents direct forged SQL inserts and immutable state changes",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      expect(()=>f.sqlite.prepare(`
        INSERT INTO processing_manual_redrives(
          id,commission_id,recovery_review_id,document_version_id,source_sha256,
          operator_subject,request_key,operator_approval_ref,request_sha256,
          authorization_sha256,image_digest,
          approval_key_thumbprint,release_key_thumbprint
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).run("fake_001","c_a",reviewId,"version_a",SHA,"president",
        "forged_redrive_01","OPR_20261119_001",SHA,SHA,
        f.env.authorization!.imageDigest,f.env.authorization!.approvalKeyThumbprint,
        f.env.authorization!.releaseKeyThumbprint)).toThrow(/MANUAL_REDRIVE_NOT_ELIGIBLE/);
      expect(()=>f.sqlite.exec(`INSERT INTO processing_manual_redrives(
        id,commission_id,recovery_review_id,document_version_id,source_sha256,
        operator_subject,request_key,operator_approval_ref,request_sha256,
        image_digest,approval_key_thumbprint,release_key_thumbprint
      ) VALUES('missing_001','c_a','${reviewId}','version_a','${SHA}',
        'operator_authorized_001','missing_auth_001','OPR_20261119_001','${SHA}',
        '${f.env.authorization!.imageDigest}',
        '${f.env.authorization!.approvalKeyThumbprint}',
        '${f.env.authorization!.releaseKeyThumbprint}')`))
        .toThrow(/MANUAL_REDRIVE_ATTESTATION_REQUIRED/);
      const result=await executeOneShotManualRedrive(f.env,f.input(reviewId));
      expect(()=>f.sqlite.exec("DELETE FROM processing_manual_redrives")).toThrow(/MANUAL_REDRIVE_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE processing_manual_redrives SET operator_subject='fake'")).toThrow(/MANUAL_REDRIVE_IMMUTABLE/);
      expect(()=>f.sqlite.prepare("UPDATE processing_manual_redrives SET authorization_sha256=?").run("0".repeat(64)))
        .toThrow(/MANUAL_REDRIVE_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE processing_manual_redrives SET state='reserved'")).toThrow(/MANUAL_REDRIVE_TRANSITION/);
      expect(()=>f.sqlite.prepare("UPDATE processing_manual_redrives SET release_key_thumbprint=?").run("A".repeat(43)))
        .toThrow(/MANUAL_REDRIVE_IMMUTABLE/);
      expect(result.state).toBe("sent");
    }finally{f.close();}
  });

  it("rejects every independently revoked operator, approval, attestation, image and signing key without reserving or sending",async()=>{
    for(const kind of ["operator","approval_ref","attestation","image","approval_key","release_key"] as const){
      const f=await fixture();
      try{
        const reviewId=await f.endorse();
        const proof=f.env.authorization!;
        const target={
          operator:proof.operatorSubject,
          approval_ref:proof.approvalRef,
          attestation:proof.attestationDigest,
          image:proof.imageDigest,
          approval_key:proof.approvalKeyThumbprint,
          release_key:proof.releaseKeyThumbprint
        }[kind];
        await registerFixtureRevocation(f,kind,target,"0001");
        await expect(executeOneShotManualRedrive(f.env,f.input(reviewId)))
          .rejects.toBeInstanceOf(ManualRedriveAccessError);
        expect(f.queue.send).not.toHaveBeenCalled();
        expect(f.attempts()).toHaveLength(0);
        expect(f.row()).toMatchObject({attempts:10});
      }finally{f.close();}
    }
  });

  it("halts a durable one-shot claim when its signing key is revoked just before Queue and never retries",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      const proof=f.env.authorization!;
      let batches=0;
      const wrapped={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          const result=await f.db.batch(statements);
          batches++;
          if(batches===1){
            await registerFixtureRevocation(f,"release_key",proof.releaseKeyThumbprint,"0002");
          }
          return result;
        }
      } as D1Database;
      const result=await executeOneShotManualRedrive({...f.env,DB:wrapped},f.input(reviewId));
      expect(result.state).toBe("halted");
      expect(f.queue.send).not.toHaveBeenCalled();
      expect(f.attempts()).toMatchObject([{
        state:"halted",authorizationDigest:proof.attestationDigest
      }]);
      await expect(executeOneShotManualRedrive(f.env,f.input(reviewId)))
        .rejects.toBeInstanceOf(ManualRedriveAccessError);
      expect(f.queue.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("fails closed when the independent D1 revocation read is unavailable",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      const wrapped={
        prepare:(query:string)=>{
          if(query.includes("processing_redrive_revocations")){
            throw new Error("Revocation database is unavailable");
          }
          return f.db.prepare(query);
        },
        batch:f.db.batch.bind(f.db)
      } as D1Database;
      await expect(executeOneShotManualRedrive({...f.env,DB:wrapped},f.input(reviewId)))
        .rejects.toBeInstanceOf(ManualRedriveAccessError);
      expect(f.queue.send).not.toHaveBeenCalled();
      expect(f.attempts()).toHaveLength(0);
    }finally{f.close();}
  });

  it("D1 atomically refuses a revocation inserted after preflight but just before the claim",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      let batches=0;
      const wrapped={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          batches++;
          if(batches===1) {
            await registerFixtureRevocation(f,"image",f.env.authorization!.imageDigest,"0004");
          }
          return f.db.batch(statements);
        }
      } as D1Database;
      await expect(executeOneShotManualRedrive({...f.env,DB:wrapped},f.input(reviewId)))
        .rejects.toBeInstanceOf(ManualRedriveConflictError);
      expect(f.attempts()).toHaveLength(0);
      expect(f.queue.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("fails closed if revocation lookup fails after the reservation",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      let batches=0;
      const wrapped={
        prepare:(query:string)=>{
          if(batches>0 && query.includes("processing_redrive_revocations"))
            throw new Error("D1 revocation read failed after claim");
          return f.db.prepare(query);
        },
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          batches++;
          return f.db.batch(statements);
        }
      } as D1Database;
      await expect(executeOneShotManualRedrive({...f.env,DB:wrapped},f.input(reviewId)))
        .rejects.toThrow(/revocation read failed/);
      expect(f.attempts()).toMatchObject([{state:"reserved"}]);
      expect(f.queue.send).not.toHaveBeenCalled();
      // A repeated request must not re-enqueue a version whose reservation
      // could have reached Queue under a different failure scenario.
      expect((await executeOneShotManualRedrive(f.env,f.input(reviewId))))
        .toMatchObject({state:"reserved",replayed:true});
      expect(f.queue.send).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("enforces append-only revocations, unique fingerprints and cannot forge a redrive through direct SQL",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      const proof=f.env.authorization!;
      await registerFixtureRevocation(f,"attestation",proof.attestationDigest,"0003");
      expect(()=>f.sqlite.exec("UPDATE processing_redrive_revocations SET incident_ref='INC_FORGED_0001'"))
        .toThrow(/REDRIVE_REVOCATION_IMMUTABLE/);
      expect(()=>f.sqlite.exec("DELETE FROM processing_redrive_revocations"))
        .toThrow(/REDRIVE_REVOCATION_IMMUTABLE/);
      expect(()=>f.sqlite.prepare(`
        INSERT INTO processing_redrive_revocations(kind,target,incident_ref)
        VALUES('attestation',?,?)
      `).run(proof.attestationDigest,"INC_REVOKE_20261119_0003")).toThrow();
      expect(()=>f.sqlite.prepare(`
        INSERT INTO processing_manual_redrives(
          id,commission_id,recovery_review_id,document_version_id,source_sha256,
          operator_subject,request_key,operator_approval_ref,request_sha256,
          authorization_sha256,image_digest,approval_key_thumbprint,release_key_thumbprint
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).run("direct_revoked_001","c_a",reviewId,"version_a",SHA,
        proof.operatorSubject,"direct_revoked_key","OPR_20261119_001",
        SHA,proof.attestationDigest,proof.imageDigest,proof.approvalKeyThumbprint,
        proof.releaseKeyThumbprint)).toThrow(/MANUAL_REDRIVE_REVOKED/);
      expect(f.attempts()).toHaveLength(0);
    }finally{f.close();}
  });

  it("the existing normal Processor accepts the same minimal Queue message, never DLQ messages",async()=>{
    const f=await fixture();
    try{
      const reviewId=await f.endorse();
      await executeOneShotManualRedrive(f.env,f.input(reviewId));
      expect(f.sent).toHaveLength(1);
      const ack=vi.fn(),retry=vi.fn();
      // No live inspector binding: the normal consumer must safely retry,
      // not mark the exhausted document ready or expose original bytes.
      const result=await processBatch({
        queue:"folio-civico-pdf-pending",
        messages:[{body:f.sent[0],ack,retry}]
      } as unknown as MessageBatch<unknown>,{
        DB:f.db,DOCUMENTS:{get:vi.fn(async()=>null)} as unknown as R2Bucket
      });
      expect(result).toMatchObject({retried:1,acked:0,invalid:0});
      expect(retry).toHaveBeenCalledOnce();
      expect(f.sqlite.prepare("SELECT extraction_status AS status FROM document_versions WHERE id='version_a'").get())
        .toMatchObject({status:"pending"});
      expect(f.row()).toMatchObject({attempts:10});
    }finally{f.close();}
  });
});
