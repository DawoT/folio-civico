import {describe,expect,it,vi} from "vitest";
import {createHash} from "node:crypto";
import {makeD1} from "../../../tests/helpers/d1";
import {persistDocumentUpload} from "../../../packages/data/src/documents";
import {openRecoveryReview,decideRecoveryReview} from "../../../packages/data/src/recovery-review";
import {processProcessingMessage,processBatch,parseProcessingMessage,type ProcessorEnv} from "./consumer";
import {serializeInspectionManifest,type InspectedTextManifest} from "../../../packages/data/src/inspected-text";

const ORIGINAL=new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
const SHA=createHash("sha256").update(ORIGINAL).digest("hex");
const SCANNER_SECRET="synthetic-inspector-consumer-key-".repeat(2);
const ASYNC_ID="00000000-0000-4000-8000-000000000012";
const MANUAL_ID="00000000-0000-4000-8000-000000000034";
const APPROVER="independent_approver";
const OPERATOR="independent_operator";
const APPROVAL_HASH="b".repeat(64);
const message=(manualRedriveId?:string)=>({
  kind:"folio.process.pdf" as const,
  versionId:"version_p5",sourceSha256:SHA,
  ...(manualRedriveId ? {manualRedriveId}:{})
});

async function fixture(){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('commission_p5','Synthetic','active');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES('commission_p5','president','president',1),
            ('commission_p5','reviewer','member',1);
    INSERT INTO document_batches(id,commission_id,label)
      VALUES('batch_p5','commission_p5','Synthetic');
  `);
  await persistDocumentUpload(f.db,{
    commissionId:"commission_p5",batchId:"batch_p5",subject:"president",
    documentId:"doc_p5",versionId:"version_p5",sha256:SHA,
    r2Key:"quarantine/synthetic-private.pdf",filename:"synthetic.pdf",
    idempotencyKey:"upload_consumer_fence_0001"
  });
  f.sqlite.exec(`
    UPDATE document_processing_outbox SET state='sent',attempts=10,
      last_sent_at='2026-11-19T12:00:00.000Z'
    WHERE document_version_id='version_p5';
  `);
  const review=await openRecoveryReview(f.db,{
    commissionId:"commission_p5",versionId:"version_p5",sourceSha256:SHA,
    actorSubject:"president",incidentRef:"INC_CONSUMER_FENCE_P5",
    requestKey:"open_consumer_p5_001"
  });
  await decideRecoveryReview(f.db,{
    commissionId:"commission_p5",reviewId:review.id,
    actorSubject:"reviewer",decision:"endorse",
    requestKey:"decide_consumer_p5_001",
    rationale:"Independent synthetic review for a consumer fence validation."
  });
  f.sqlite.prepare(`
    INSERT INTO processing_async_redrive_requests(
      id,commission_id,recovery_review_id,operator_subject,request_key,
      approval_ref,expires_at,institutional_gate_required
    ) VALUES(?,?,?,?,?,'OPR_CONSUMER_FENCE_P5',unixepoch()+300,1)
  `).run(ASYNC_ID,"commission_p5",review.id,OPERATOR,"redrive_consumer_p5_001");
  f.sqlite.prepare(`
    INSERT INTO processing_async_redrive_approvals(
      request_id,operator_subject,approver_subject,approval_sha256,
      approval_key_thumbprint
    ) VALUES(?,?,?,?,?)
  `).run(ASYNC_ID,OPERATOR,APPROVER,APPROVAL_HASH,"A".repeat(43));
  f.sqlite.prepare(`
    INSERT INTO processing_institutional_approval_evidence(
      purpose,request_id,actor_subject,approver_subject,
      scope_sha256,approval_sha256,case_revision,checked_at,expires_at
    )
    SELECT 'redrive',id,operator_subject,?,?,?,12,unixepoch(),expires_at
    FROM processing_async_redrive_requests WHERE id=?
  `).run(APPROVER,SHA,APPROVAL_HASH,ASYNC_ID);
  f.sqlite.prepare(`
    UPDATE processing_async_redrive_requests
      SET status='approved',approver_subject=?,approval_sha256=?,
          approval_key_thumbprint=?,approved_at=unixepoch()
      WHERE id=?
  `).run(APPROVER,APPROVAL_HASH,"A".repeat(43),ASYNC_ID);
  f.sqlite.prepare(`
    INSERT INTO processing_manual_redrives(
      id,commission_id,recovery_review_id,document_version_id,source_sha256,
      operator_subject,request_key,operator_approval_ref,request_sha256,
      authorization_sha256,image_digest,approval_key_thumbprint,
      release_key_thumbprint,async_request_id,async_approval_sha256
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    MANUAL_ID,"commission_p5",review.id,"version_p5",SHA,OPERATOR,
    "redrive_consumer_p5_001","OPR_CONSUMER_FENCE_P5",SHA,
    SHA,"sha256:"+SHA,"A".repeat(43),"B".repeat(43),
    ASYNC_ID,APPROVAL_HASH
  );
  const manifest:InspectedTextManifest={
    documentVersionId:"version_p5",sourceSha256:SHA,scanVerdict:"clean",
    scanner:"synthetic-scanner-v1",scannerReportId:"synthetic_report_001",
    scannedAt:"2026-11-19T12:00:00.000Z",
    pages:[{page:1,text:"Confirmed synthetic content"}]
  };
  const key=await crypto.subtle.importKey(
    "raw",new TextEncoder().encode(SCANNER_SECRET),
    {name:"HMAC",hash:"SHA-256"},false,["sign"]
  );
  const sig=new Uint8Array(await crypto.subtle.sign(
    "HMAC",key,new Uint8Array(serializeInspectionManifest(manifest)).buffer
  ));
  const signature=[...sig].map(n=>n.toString(16).padStart(2,"0")).join("");
  const get=vi.fn(async()=>({
    size:ORIGINAL.length,
    arrayBuffer:async()=>ORIGINAL.buffer.slice(
      ORIGINAL.byteOffset,ORIGINAL.byteOffset+ORIGINAL.length
    )
  }));
  const inspectorFetch=vi.fn(async()=>Response.json({manifest,signature}));
  const env:ProcessorEnv={
    DB:f.db,DOCUMENTS:{get} as unknown as R2Bucket,
    INSPECTOR:{fetch:inspectorFetch} as unknown as Fetcher,
    INSPECTOR_SERVICE_TOKEN:"synthetic-inspector-service-token-".repeat(2),
    INSPECTOR_HMAC_KEY:SCANNER_SECRET
  };
  const invalidate=()=>f.sqlite.prepare(`
    INSERT INTO processing_institutional_approval_invalidations(
      purpose,request_id,case_revision,reason,evidence_sha256
    ) VALUES('redrive',?,12,'case_closed',?)
  `).run(ASYNC_ID,"d".repeat(64));
  return {...f,env,get,invalidate,inspectorFetch,manifest,signature};
}

function syntheticR27Revocation(
  f:Awaited<ReturnType<typeof fixture>>,
  kind:"operator"|"approval_ref"|"attestation"|"image"|"approval_key"|"release_key",
  target:string
):void{
  const incident="INC_CONSUMER_SQL_FENCE_P6";
  f.sqlite.prepare(`
    INSERT INTO processing_redrive_revocation_actions(
      actor_subject,request_key,kind,target,incident_ref,approver_subject,
      target_sha256,reason_sha256,approval_sha256,
      approval_key_thumbprint,payload_sha256
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
  `).run("synthetic_registrar","revocation_sql_fence_001",kind,target,
    incident,"independent_registrar",SHA,SHA,SHA,"C".repeat(43),SHA);
  f.sqlite.prepare(`
    INSERT INTO processing_redrive_revocations(kind,target,incident_ref)
    VALUES(?,?,?)
  `).run(kind,target,incident);
}
function insertSyntheticReport(f:Awaited<ReturnType<typeof fixture>>):void{
  f.sqlite.prepare(`
    INSERT INTO document_processing_reports(
      document_version_id,scanner_name,scanner_report_id,scanned_at,
      source_sha256,manifest_sha256,page_count
    ) VALUES('version_p5','synthetic-scanner','report_sql_fence_p6',
      '2026-11-19T10:00:00.000Z',?,?,1)
  `).run(SHA,SHA);
}

describe("R2.12b/P6 transactional consumer authority fence",()=>{
  it("halts a redrive 422 outcome when commission closes during inspection",async()=>{
    const f=await fixture();
    try {
      f.inspectorFetch.mockImplementationOnce(async()=>{
        f.sqlite.prepare(
          "UPDATE commissions SET status='closed' WHERE id='commission_p5'"
        ).run();
        return new Response(null,{status:422});
      });
      expect(await processProcessingMessage(message(MANUAL_ID),f.env)).toBe("stale");
      expect(f.sqlite.prepare(
        "SELECT extraction_status FROM document_versions WHERE id='version_p5'"
      ).get()).toMatchObject({extraction_status:"pending"});
      expect(f.sqlite.prepare(
        "SELECT count(*) AS n FROM audit_events WHERE action='document.inspection_rejected'"
      ).get()).toMatchObject({n:0});
    }finally{f.close();}
  });

  it("rejects a report and 422 state write when the SQL clock exceeds approval expiry",async()=>{
    const f=await fixture();
    try{
      const row=f.sqlite.prepare(`
        SELECT expires_at AS expiresAt FROM processing_async_redrive_requests
        WHERE id=?
      `).get(ASYNC_ID) as {expiresAt:number};
      // Simulate the DB crossing the real proposal TTL between the
      // consumer's JS preflight and its final, atomic SQL write.
      f.sqlite.function("unixepoch",()=>row.expiresAt+1);
      expect(()=>insertSyntheticReport(f))
        .toThrow(/REDRIVE_CONSUMER_AUTHORITY_DENIED/);
      expect(()=>f.sqlite.exec(`
        UPDATE document_versions SET extraction_status='needs_review'
        WHERE id='version_p5'
      `)).toThrow(/REDRIVE_CONSUMER_AUTHORITY_DENIED/);
      expect(f.sqlite.prepare(
        "SELECT count(*) AS n FROM document_processing_reports"
      ).get()).toMatchObject({n:0});
      expect(f.sqlite.prepare(
        "SELECT extraction_status FROM document_versions WHERE id='version_p5'"
      ).get()).toMatchObject({extraction_status:"pending"});
    }finally{f.close();}
  });

  it.each([
    ["operator",OPERATOR],
    ["operator",APPROVER],
    ["approval_ref","OPR_CONSUMER_FENCE_P5"],
    ["attestation",SHA],
    ["image","sha256:"+SHA],
    ["approval_key","A".repeat(43)],
    ["release_key","B".repeat(43)]
  ] as const)("blocks %s revocation for target %s in SQL report and status writes",async(kind,target)=>{
    const f=await fixture();
    try{
      syntheticR27Revocation(f,kind,target);
      expect(()=>insertSyntheticReport(f))
        .toThrow(/REDRIVE_CONSUMER_AUTHORITY_DENIED/);
      expect(()=>f.sqlite.exec(`
        UPDATE document_versions SET extraction_status='needs_review'
        WHERE id='version_p5'
      `)).toThrow(/REDRIVE_CONSUMER_AUTHORITY_DENIED/);
      expect(f.sqlite.prepare(
        "SELECT count(*) AS n FROM document_processing_reports"
      ).get()).toMatchObject({n:0});
      expect(f.sqlite.prepare(
        "SELECT extraction_status FROM document_versions WHERE id='version_p5'"
      ).get()).toMatchObject({extraction_status:"pending"});
    }finally{f.close();}
  });

  it("rolls back signed pages and audit if authority is revoked after consumer preflight",async()=>{
    const f=await fixture();
    try{
      let raced=false;
      const db={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          if(!raced){
            raced=true;
            syntheticR27Revocation(f,"operator",APPROVER);
          }
          return f.db.batch(statements);
        }
      } as unknown as D1Database;
      const outcome=await processProcessingMessage(message(MANUAL_ID),{
        ...f.env,DB:db
      });
      expect(raced).toBe(true);
      expect(outcome).toBe("stale");
      expect(f.inspectorFetch).toHaveBeenCalledOnce();
      expect(f.sqlite.prepare(
        "SELECT count(*) AS n FROM document_processing_reports"
      ).get()).toMatchObject({n:0});
      expect(f.sqlite.prepare(
        "SELECT count(*) AS n FROM document_pages"
      ).get()).toMatchObject({n:0});
      expect(f.sqlite.prepare(
        "SELECT extraction_status FROM document_versions WHERE id='version_p5'"
      ).get()).toMatchObject({extraction_status:"pending"});
      expect(f.sqlite.prepare(
        "SELECT count(*) AS n FROM audit_events WHERE action='document.inspected_text_admitted'"
      ).get()).toMatchObject({n:0});
    }finally{f.close();}
  });

  it("blocks a halted reservation in D1 even if message passed earlier preflight",async()=>{
    const f=await fixture();
    try{
      f.sqlite.prepare(`
        UPDATE processing_manual_redrives
        SET state='halted',outcome_at=? WHERE id=?
      `).run(new Date().toISOString(),MANUAL_ID);
      expect(()=>insertSyntheticReport(f))
        .toThrow(/REDRIVE_CONSUMER_AUTHORITY_DENIED/);
      expect(()=>f.sqlite.exec(`
        UPDATE document_versions SET extraction_status='needs_review'
        WHERE id='version_p5'
      `)).toThrow(/REDRIVE_CONSUMER_AUTHORITY_DENIED/);
    }finally{f.close();}
  });
});

describe("R2.12b/P5 consumer provenance and institutional cancellation fencing",()=>{
  it("blocks a one-shot whose operator was revoked after Queue enqueue",async()=>{
    const f=await fixture();
    try{
      f.sqlite.prepare(`
        INSERT INTO processing_redrive_revocation_actions(
          actor_subject,request_key,kind,target,incident_ref,approver_subject,
          target_sha256,reason_sha256,approval_sha256,
          approval_key_thumbprint,payload_sha256
        ) VALUES(?,?,'operator',?,?,?,?,?,?,?,?)
      `).run("synthetic_registrar","revoke_post_enqueue_p5",OPERATOR,
        "INC_REVOKE_CONSUMER_P5","another_registrar",SHA,SHA,SHA,
        "C".repeat(43),SHA);
      f.sqlite.prepare(`
        INSERT INTO processing_redrive_revocations(kind,target,incident_ref)
        VALUES('operator',?,?)
      `).run(OPERATOR,"INC_REVOKE_CONSUMER_P5");
      expect(await processProcessingMessage(message(MANUAL_ID),f.env))
        .toBe("stale");
      expect(f.get).not.toHaveBeenCalled();
      expect(f.inspectorFetch).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("acks a permanently invalidated redrive but retries a D1 outage without inspecting R2",async()=>{
    const f=await fixture();
    try{
      f.invalidate();
      const ack=vi.fn(),retry=vi.fn();
      const batch={
        queue:"folio-civico-pdf-pending",
        messages:[{body:message(MANUAL_ID),ack,retry}]
      } as unknown as MessageBatch<unknown>;
      expect(await processBatch(batch,f.env)).toEqual({
        acked:1,retried:0,invalid:0
      });
      expect(ack).toHaveBeenCalledOnce();
      expect(retry).not.toHaveBeenCalled();
      expect(f.get).not.toHaveBeenCalled();
      const unavailable={
        ...f.env,DB:{
          prepare:()=>{throw new Error("D1 consumer outage");}
        } as unknown as D1Database
      };
      const ack2=vi.fn(),retry2=vi.fn();
      const retryBatch={
        queue:"folio-civico-pdf-pending",
        messages:[{body:message(MANUAL_ID),ack:ack2,retry:retry2}]
      } as unknown as MessageBatch<unknown>;
      expect(await processBatch(retryBatch,unavailable)).toEqual({
        acked:0,retried:1,invalid:0
      });
      expect(retry2).toHaveBeenCalledOnce();
      expect(ack2).not.toHaveBeenCalled();
      expect(f.get).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("does not send quarantined original to inspector if invalidation arrives during R2 retrieval",async()=>{
    const f=await fixture();
    try{
      f.get.mockImplementationOnce(async()=>{
        f.invalidate();
        return {
          size:ORIGINAL.length,
          arrayBuffer:async()=>ORIGINAL.buffer.slice(
            ORIGINAL.byteOffset,ORIGINAL.byteOffset+ORIGINAL.length
          )
        };
      });
      expect(await processProcessingMessage(message(MANUAL_ID),f.env))
        .toBe("stale");
      expect(f.get).toHaveBeenCalledOnce();
      expect(f.inspectorFetch).not.toHaveBeenCalled();
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:0});
    }finally{f.close();}
  });
  it("denies a halted one-shot even without an institutional invalidation row",async()=>{
    const f=await fixture();
    try{
      f.sqlite.prepare(`
        UPDATE processing_manual_redrives
          SET state='halted',outcome_at=?
        WHERE id=?
      `).run(new Date().toISOString(),MANUAL_ID);
      expect(await processProcessingMessage(message(MANUAL_ID),f.env))
        .toBe("stale");
      expect(f.get).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("rejects a cancellation arriving during inspection before publishing text",async()=>{
    const f=await fixture();
    try{
      f.inspectorFetch.mockImplementationOnce(async()=>{
        f.invalidate();
        return Response.json({manifest:f.manifest,signature:f.signature});
      });
      expect(await processProcessingMessage(message(MANUAL_ID),f.env))
        .toBe("stale");
      expect(f.inspectorFetch).toHaveBeenCalledOnce();
      expect(f.sqlite.prepare(
        "SELECT extraction_status FROM document_versions WHERE id='version_p5'"
      ).get()).toMatchObject({extraction_status:"pending"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get())
        .toMatchObject({n:0});
    }finally{f.close();}
  });
  it("rolls back a cancelled inspection when invalidation races the final D1 batch",async()=>{
    const f=await fixture();
    try{
      let inserted=false;
      const raced={
        prepare:f.db.prepare.bind(f.db),
        batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
          if(!inserted){
            f.invalidate();
            inserted=true;
          }
          return f.db.batch(statements);
        }
      } as unknown as D1Database;
      const outcome=await processProcessingMessage(message(MANUAL_ID),{
        ...f.env,DB:raced
      });
      expect(outcome).toBe("stale");
      expect(inserted).toBe(true);
      expect(f.inspectorFetch).toHaveBeenCalledOnce();
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:0});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get())
        .toMatchObject({n:0});
      expect(f.sqlite.prepare(
        "SELECT extraction_status FROM document_versions WHERE id='version_p5'"
      ).get()).toMatchObject({extraction_status:"pending"});
    }finally{f.close();}
  });
  it("does not persist a 422 unsafe result after a cancellation during inspection",async()=>{
    const f=await fixture();
    try{
      f.inspectorFetch.mockImplementationOnce(async()=>{
        f.invalidate();
        return new Response(null,{status:422});
      });
      expect(await processProcessingMessage(message(MANUAL_ID),f.env))
        .toBe("stale");
      expect(f.sqlite.prepare(
        "SELECT extraction_status FROM document_versions WHERE id='version_p5'"
      ).get()).toMatchObject({extraction_status:"pending"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:0});
    }finally{f.close();}
  });

  it("requires a valid opaque manual-redrive tag and never downgrades it into an ordinary outbox message",async()=>{
    const f=await fixture();
    try{
      expect(parseProcessingMessage(message(MANUAL_ID))).toMatchObject({
        manualRedriveId:MANUAL_ID
      });
      for(const bad of [
        message(),message("00000000-0000-4000-8000-000000000099"),
      ]){
        expect(await processProcessingMessage(bad,f.env)).toBe("stale");
      }
      for(const bad of [
        {...message(MANUAL_ID),extra:true},
        {...message(MANUAL_ID),manualRedriveId:"not-uuid"},
        {...message(MANUAL_ID),manualRedriveId:null}
      ])expect(parseProcessingMessage(bad)).toBeNull();
      expect(f.get).not.toHaveBeenCalled();
      expect(await processProcessingMessage(message(MANUAL_ID),f.env))
        .toBe("completed");
      expect(f.get).toHaveBeenCalled();
      expect(f.inspectorFetch).toHaveBeenCalledOnce();
      expect(f.sqlite.prepare(
        "SELECT extraction_status FROM document_versions WHERE id='version_p5'"
      ).get()).toMatchObject({extraction_status:"ready"});
    }finally{f.close();}
  });
  it("acks an invalidated one-shot before accessing R2 and retries only on D1 read outage",async()=>{
    const f=await fixture();
    try{
      f.invalidate();
      expect(await processProcessingMessage(message(MANUAL_ID),f.env))
        .toBe("stale");
      expect(f.get).not.toHaveBeenCalled();
      const unavailable={
        ...f.env,
        DB:{prepare:()=>{throw new Error("D1 offline");}} as unknown as D1Database
      };
      await expect(processProcessingMessage(message(MANUAL_ID),unavailable))
        .rejects.toThrow(/D1 offline/);
      expect(f.get).not.toHaveBeenCalled();
    }finally{f.close();}
  });
  it("rejects inspection report insertion and unsafe status update after an invalidation",async()=>{
    const f=await fixture();
    try{
      f.invalidate();
      expect(()=>f.sqlite.prepare(`
        INSERT INTO document_processing_reports(
          document_version_id,scanner_name,scanner_report_id,scanned_at,
          source_sha256,manifest_sha256,page_count
        ) VALUES('version_p5','synthetic-scanner','report_consumer_p5',
          '2026-11-19T10:00:00.000Z',?,?,1)
      `).run(SHA,SHA)).toThrow(/INSTITUTIONAL_REDRIVE_INVALIDATED/);
      expect(()=>f.sqlite.exec(`
        UPDATE document_versions SET extraction_status='needs_review'
        WHERE id='version_p5'
      `)).toThrow(/INSTITUTIONAL_REDRIVE_INVALIDATED/);
      expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='version_p5'").get())
        .toMatchObject({extraction_status:"pending"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:0});
    }finally{f.close();}
  });
});
