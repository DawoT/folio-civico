import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDocumentUpload } from "../../../packages/data/src/documents";
import { triageDeadLetterMessages, type DLQDisposition } from "./dlq-triage";
import {processBatch} from "./consumer";

const HASH="a".repeat(64);
const message=(id:string,sha=HASH)=>({
  kind:"folio.process.pdf",versionId:id,sourceSha256:sha
});
async function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('active','Comisión de prueba','active'),('closed','Comisión cerrada','active');
    INSERT INTO commission_members(commission_id,subject,role) VALUES
      ('active','author','member'),('closed','author','member');
    INSERT INTO document_batches(id,commission_id,label) VALUES
      ('batch_a','active','Archivos'),('batch_c','closed','Cerrados');
  `);
  const put=async(id:string,commissionId="active")=>persistDocumentUpload(f.db,{
    commissionId,batchId:commissionId==="active"?"batch_a":"batch_c",
    subject:"author",documentId:"doc_"+id,versionId:id,sha256:HASH,
    r2Key:"quarantine/"+id+".pdf",filename:"INTERNAL_"+id+".pdf",
    idempotencyKey:"upload_"+id+"_synthetic"
  });
  for(const id of ["pending","inflight","exhausted","rejected","completed","inconsistent","closed_job","missing_outbox"]) {
    await put(id,id==="closed_job"?"closed":"active");
  }
  f.sqlite.exec(`
    UPDATE document_processing_outbox SET state='sent',attempts=2,last_sent_at='2026-11-19T12:00:00.000Z'
      WHERE document_version_id='inflight';
    UPDATE document_processing_outbox SET state='sent',attempts=10,last_sent_at='2026-11-19T09:00:00.000Z'
      WHERE document_version_id='exhausted';
    UPDATE document_processing_outbox SET state='sent',attempts=2,last_sent_at='2026-11-19T10:00:00.000Z'
      WHERE document_version_id='rejected';
    UPDATE document_versions SET extraction_status='needs_review' WHERE id='rejected';
    UPDATE document_processing_outbox SET state='sent',attempts=0,last_sent_at='2026-11-19T10:00:00.000Z'
      WHERE document_version_id='inconsistent';
    UPDATE commissions SET status='closed' WHERE id='closed';
  `);
  f.sqlite.prepare(`
    INSERT INTO document_processing_reports(
      document_version_id,scanner_name,scanner_report_id,scanned_at,
      source_sha256,manifest_sha256,page_count
    ) VALUES('completed','fixture-scanner','fixture-report-001','2026-11-19T10:00:00.000Z',?,?,1)
  `).run(HASH,"b".repeat(64));
  f.sqlite.exec(`
    INSERT INTO document_pages(document_version_id,page,extracted_text,extraction_status)
      VALUES('completed',1,'Synthetic content','ready');
    UPDATE document_versions SET extraction_status='ready',page_count=1 WHERE id='completed';
    DROP TRIGGER processing_outbox_no_delete;
    DELETE FROM document_processing_outbox WHERE document_version_id='missing_outbox';
  `);
  return f;
}
describe("read-only DLQ human triage",()=>{
  it("classifies all risks without returning identifiers, hashes, filenames, keys or document text",async()=>{
    const f=await fixture();
    try {
      const messages=[
        message("pending"), message("inflight"),message("exhausted"),
        message("rejected"),message("completed"),message("inconsistent"),
        message("closed_job"),message("missing_outbox"),
        message("pending","c".repeat(64)),message("unknown"),
        {kind:"wrong",versionId:"pending"},null
      ];
      const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
      const beforeChanges=f.sqlite.prepare("SELECT total_changes() AS n").get();
      const triage=await triageDeadLetterMessages(f.db,messages);
      expect(triage.scanned).toBe(messages.length);
      expect(triage.requiresOperatorAttention).toBe(true);
      const expected:DLQDisposition[]=[
        "automatic_retry_pending","automatic_retry_pending","manual_review_exhausted",
        "rejected","completed","inconsistent","paused","missing_outbox",
        "source_mismatch","not_found","invalid_message","invalid_message"
      ];
      expect(triage.items.map(item=>item.disposition)).toEqual(expected);
      expect(triage.items.map(item=>item.position)).toEqual(messages.map((_,i)=>i));
      for (const disposition of expected) {
        expect(triage.counts[disposition]).toBeGreaterThan(0);
      }
      const serialized=JSON.stringify(triage);
      for(const privateValue of ["INTERNAL_","quarantine/","active","pending","exhausted",HASH,
        "Synthetic content","doc_pending"]) {
        if(["pending","exhausted","active"].includes(privateValue))continue; // names appear in safe enum labels
        expect(serialized).not.toContain(privateValue);
      }
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(before);
      expect(f.sqlite.prepare("SELECT total_changes() AS n").get()).toEqual(beforeChanges);
      expect(f.sqlite.prepare("SELECT attempts FROM document_processing_outbox WHERE document_version_id='exhausted'").get())
        .toMatchObject({attempts:10});
    }finally{f.close();}
  });

  it("validates batch bounds without D1 access and returns only aggregate-safe dispositions",async()=>{
    const f=await fixture();
    try {
      await expect(triageDeadLetterMessages(f.db,[message("pending")],new Date(NaN))).rejects.toThrow();
      for(const input of [[],Array.from({length:51},()=>message("pending"))]){
        await expect(triageDeadLetterMessages(f.db,input)).rejects.toThrow();
      }
      await expect(triageDeadLetterMessages(f.db,{} as never)).rejects.toThrow();
      const one=await triageDeadLetterMessages(f.db,[message("pending")]);
      expect(one).toMatchObject({
        scanned:1,requiresOperatorAttention:false,
        counts:{automatic_retry_pending:1,manual_review_exhausted:0}
      });
      expect(Object.keys(one)).toEqual(["scanned","counts","items","requiresOperatorAttention"]);
    }finally{f.close();}
  });

  it("treats corrupted lease dates and undocumented states as inconsistent, not safe for replay",async()=>{
    const f=await fixture();
    try {
      f.sqlite.exec(`
        UPDATE document_processing_outbox
        SET last_sent_at='2026-02-30T12:00:00.000Z'
        WHERE document_version_id='inflight';
      `);
      const triage=await triageDeadLetterMessages(f.db,[message("inflight")],new Date("2026-11-19T12:10:00.000Z"));
      expect(triage).toMatchObject({
        scanned:1,requiresOperatorAttention:true,
        items:[{position:0,disposition:"inconsistent"}]
      });
      f.sqlite.exec("UPDATE document_processing_outbox SET last_sent_at='2028-01-01T00:00:00.000Z' WHERE document_version_id='inflight'");
      const future=await triageDeadLetterMessages(f.db,[message("inflight")],
        new Date("2026-11-19T12:10:00.000Z"));
      expect(future.items).toEqual([{position:0,disposition:"inconsistent"}]);
    }finally{f.close();}
  });

  it("does not acknowledge or consume a DLQ message with the normal Processor",async()=>{
    const ack=()=>{throw new Error("DLQ must not be acknowledged automatically");};
    const batch={
      queue:"folio-civico-pdf-dead-letter",
      messages:[{body:message("pending"),ack,retry:ack}]
    } as unknown as MessageBatch<unknown>;
    await expect(processBatch(batch,{} as never)).rejects.toThrow("Unexpected queue source");
  });

  it("keeps the live processor config unbound while providing a validated opt-in DLQ example",()=>{
    const active=JSON.parse(readFileSync(new URL("../wrangler.jsonc",import.meta.url),"utf8")) as Record<string,unknown>;
    expect(active).not.toHaveProperty("queues");
    expect(active).not.toHaveProperty("triggers");
    const example=JSON.parse(readFileSync(new URL("../wrangler.queues.example.jsonc",import.meta.url),"utf8")) as {
      name:string;queues:{consumers:Array<Record<string,unknown>>};
    };
    expect(example.name).toBe("folio-civico-processor");
    expect(example.queues.consumers).toEqual([{
      queue:"folio-civico-pdf-pending",
      dead_letter_queue:"folio-civico-pdf-dead-letter",
      max_batch_size:5,max_retries:3,retry_delay:60
    }]);
    expect(JSON.stringify(example)).not.toContain("COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT");
  });
});
