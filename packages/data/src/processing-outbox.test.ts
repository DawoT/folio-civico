import { describe,expect,it,vi } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import {persistDocumentUpload} from "./documents";
import {dispatchProcessingOutbox} from "./processing-outbox";

const sha="a".repeat(64);
function fixture() {
 const f=makeD1();
 f.sqlite.exec(`
 INSERT INTO commissions(id,name,status) VALUES ('c_a','Synthetic','active');
 INSERT INTO commission_members(commission_id,subject,role) VALUES ('c_a','reviewer','member');
 INSERT INTO document_batches(id,commission_id,label) VALUES ('b_a','c_a','Cases');
 `); 
 const send=vi.fn(async(_message:unknown)=>undefined);
 const queue={send} as unknown as Queue;
 return {...f,send,queue};
}
async function create(db:D1Database,versionId="v_a",requestKey="upload_processing_01"){
 await persistDocumentUpload(db,{
  commissionId:"c_a",batchId:"b_a",subject:"reviewer",documentId:"doc_"+versionId,
  versionId,sha256:sha,r2Key:"quarantine/"+versionId+".pdf",filename:"synthetic.pdf",
  idempotencyKey:requestKey
 });
}
describe("transactional PDF processing outbox",()=>{
 it("creates a durable pending job in the same upload transaction",async()=>{
  const f=fixture();
  try {
   await create(f.db);
   expect(f.sqlite.prepare("SELECT document_version_id,state,attempts FROM document_processing_outbox").get())
    .toMatchObject({document_version_id:"v_a",state:"pending",attempts:0});
   expect(f.sqlite.prepare("SELECT count(*) as n FROM audit_events").get()).toMatchObject({n:1});
  }finally{f.close();}
 });
 it("refuses fabricated job completion or deletion without a signed report",async()=>{
  const f=fixture();
  try {
    await create(f.db);
    expect(()=>f.sqlite.exec("UPDATE document_processing_outbox SET state='completed' WHERE document_version_id='v_a'"))
      .toThrow(/OUTBOX_COMPLETION_REQUIRES_INSPECTION_REPORT/);
    expect(()=>f.sqlite.exec("DELETE FROM document_processing_outbox WHERE document_version_id='v_a'"))
      .toThrow(/PROCESSING_JOB_RETENTION_REQUIRED/);
    expect(()=>f.sqlite.exec("UPDATE document_processing_outbox SET document_version_id='v_fake' WHERE document_version_id='v_a'"))
      .toThrow(/PROCESSING_JOB_ID_IMMUTABLE/);
  }finally{f.close();}
 });

 it("sends bounded messages without original object keys or PDF bytes",async()=>{
  const f=fixture();
  try {
   await create(f.db);
   const result=await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-18T17:00:00.000Z"));
   expect(result).toMatchObject({sent:1,failed:0});
   expect(f.send).toHaveBeenCalledOnce();
   expect(f.send).toHaveBeenCalledWith({kind:"folio.process.pdf",versionId:"v_a",sourceSha256:sha});
   expect(JSON.stringify(f.send.mock.calls)).not.toContain("quarantine/");
   expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
    .toMatchObject({state:"sent",attempts:1});
  }finally{f.close();}
 });
 it("retries an unconfirmed message after a lease, preserving at-least-once delivery",async()=>{
  const f=fixture();
  try {
   await create(f.db);
   const time=new Date("2026-11-18T17:00:00.000Z");
   await dispatchProcessingOutbox(f.db,f.queue,time);
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date(time.getTime()+60_000))).sent).toBe(0);
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date(time.getTime()+16*60_000))).sent).toBe(1);
   expect(f.send).toHaveBeenCalledTimes(2);
  }finally{f.close();}
 });
 it("does not mark an unsent message as sent when queue fails",async()=>{
  const f=fixture();
  try {
   await create(f.db);
   f.send.mockRejectedValueOnce(new Error("Queue unavailable"));
   const result=await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-18T17:00:00.000Z"));
   expect(result).toMatchObject({sent:0,failed:1});
   expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
    .toMatchObject({state:"pending",attempts:0});
  }finally{f.close();}
 });
 it("does not requeue finished or closed-commission documents",async()=>{
  const f=fixture();
  try {
   await create(f.db);
   f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
   expect((await dispatchProcessingOutbox(f.db,f.queue)).sent).toBe(0);
   expect(f.send).not.toHaveBeenCalled();
  }finally{f.close();}
 });
 it("caps attempts and never loops unbounded",async()=>{
  const f=fixture();
  try {
   await create(f.db);
   f.sqlite.exec("UPDATE document_processing_outbox SET attempts=10, state='sent', last_sent_at='2026-01-01T00:00:00.000Z'");
   expect((await dispatchProcessingOutbox(f.db,f.queue)).sent).toBe(0);
   expect(f.send).not.toHaveBeenCalled();
  }finally{f.close();}
 });
});
