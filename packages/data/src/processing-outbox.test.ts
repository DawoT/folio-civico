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
 it("atomically claims each version before awaiting Queue, preventing concurrent cron duplication",async()=>{
  const f=fixture();
  let releaseSend:()=>void=()=>undefined;
  try {
   await create(f.db);
   const queued=new Promise<void>(resolve=>{releaseSend=resolve;});
   let entered:()=>void=()=>undefined;
   const enteredSend=new Promise<void>(resolve=>{entered=resolve;});
   f.send.mockImplementationOnce(async()=>{entered();await queued;});
   const time=new Date("2026-11-19T12:00:00.000Z");
   const first=dispatchProcessingOutbox(f.db,f.queue,time);
   await enteredSend;
   // A second scheduled event cannot send the same job while the first network
   // call is unresolved; it must observe the durable D1 lease.
   expect(f.sqlite.prepare("SELECT state,attempts,last_sent_at AS lastSentAt FROM document_processing_outbox").get())
    .toMatchObject({state:"sent",attempts:1,lastSentAt:time.toISOString()});
   const second=await dispatchProcessingOutbox(f.db,f.queue,time);
   expect(second.sent).toBe(0);
   expect(f.send).toHaveBeenCalledOnce();
   releaseSend();
   expect((await first).sent).toBe(1);
   expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
    .toMatchObject({state:"sent",attempts:1});
  }finally{
   releaseSend();f.close();
  }
 });
 it("restores a failed network claim immediately without consuming a retry attempt",async()=>{
  const f=fixture();
  try {
   await create(f.db);
   f.send.mockImplementationOnce(async()=>{
    expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
     .toMatchObject({state:"sent",attempts:1});
    throw new Error("Queue unavailable during send");
   });
   expect(await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:00:00.000Z")))
    .toMatchObject({selected:1,sent:0,failed:1});
   expect(f.sqlite.prepare("SELECT state,attempts,last_sent_at AS lastSentAt FROM document_processing_outbox").get())
    .toMatchObject({state:"pending",attempts:0,lastSentAt:null});
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:01:00.000Z"))).sent)
    .toBe(1);
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
 it("recovers a lease reserved by a crashed scheduler only after 15 minutes",async()=>{
  const f=fixture();
  try {
   await create(f.db);
   const reservedAt="2026-11-19T12:00:00.000Z";
   // Simulate a process crash after atomic D1 claim but before Queue.send.
   f.sqlite.prepare(`
     UPDATE document_processing_outbox
     SET state='sent',attempts=1,last_sent_at=?
     WHERE document_version_id='v_a'
   `).run(reservedAt);
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:14:59.000Z"))).selected).toBe(0);
   expect(f.send).not.toHaveBeenCalled();
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:15:01.000Z"))).sent).toBe(1);
   expect(f.send).toHaveBeenCalledOnce();
   expect(f.sqlite.prepare("SELECT state,attempts,last_sent_at AS lastSentAt FROM document_processing_outbox").get())
    .toMatchObject({state:"sent",attempts:2,lastSentAt:"2026-11-19T12:15:01.000Z"});
  }finally{f.close();}
 });
 it("does not reopen a job rejected by a concurrent consumer after an enqueue failure",async()=>{
  const f=fixture();
  try{
   await create(f.db);
   f.send.mockImplementationOnce(async()=>{
    f.sqlite.exec("UPDATE document_versions SET extraction_status='needs_review' WHERE id='v_a'");
    throw new Error("Ambiguous Queue network failure");
   });
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:00:00.000Z"))).failed).toBe(1);
   expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
    .toMatchObject({state:"sent",attempts:1});
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:16:00.000Z"))).selected).toBe(0);
   expect(f.send).toHaveBeenCalledOnce();
  }finally{f.close();}
 });
 it("will not dispatch inconsistent pending/sent rows without a valid lease shape",async()=>{
  const f=fixture();
  try{
   await create(f.db);
   f.sqlite.exec("UPDATE document_processing_outbox SET state='sent',attempts=0,last_sent_at='2025-01-01T00:00:00.000Z'");
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:00:00.000Z"))).selected).toBe(0);
   f.sqlite.exec("UPDATE document_processing_outbox SET state='pending',attempts=1,last_sent_at=NULL");
   expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:16:00.000Z"))).selected).toBe(0);
   expect(f.send).not.toHaveBeenCalled();
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
