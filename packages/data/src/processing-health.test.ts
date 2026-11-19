import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {auditProcessingBacklog} from "./processing-health";

const NOW=new Date("2026-11-18T17:30:00.000Z");

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('c_active','Active','active'),('c_closed','Closed','closed');
    INSERT INTO document_batches(id,commission_id,label)
      VALUES('b_active','c_active','Cases'),('b_closed','c_closed','Old');
  `);
  function add(id:string,created:string,commission="c_active"){
    const batch=commission==="c_closed"?"b_closed":"b_active";
    f.sqlite.prepare(`INSERT INTO documents(id,commission_id,batch_id,filename) VALUES(?,?,?,?)`)
      .run("doc_"+id,commission,batch,"PRIVATE_FILENAME_"+id+".pdf");
    f.sqlite.prepare(`
      INSERT INTO document_versions(id,document_id,version_number,sha256,r2_object_key,created_at)
      VALUES(?, ?, 1, ?, ?, ?)
    `).run(id,"doc_"+id,"a".repeat(64),"quarantine/PRIVATE_KEY_"+id+".pdf",created);
    f.sqlite.prepare("UPDATE document_processing_outbox SET created_at=? WHERE document_version_id=?")
      .run(created,id);
  }
  const makeSent=(id:string,attempts:number,at:string|null)=>{
    f.sqlite.prepare(`UPDATE document_processing_outbox
      SET state='sent',attempts=?,last_sent_at=? WHERE document_version_id=?`).run(attempts,at,id);
  };
  function ready(id:string) {
    f.sqlite.prepare(`INSERT INTO document_processing_reports
      (document_version_id,scanner_name,scanner_report_id,scanned_at,
       source_sha256,manifest_sha256,page_count)
      VALUES(?,'isolated-scanner-v1',?,'2026-11-18T16:00:00.000Z',?,?,1)`)
      .run(id,"scan_"+id+"_001","a".repeat(64),"b".repeat(64));
    f.sqlite.prepare(`INSERT INTO document_pages
      (document_version_id,page,extracted_text,extraction_status)
      VALUES(?,1,'Synthetic processed text','ready')`).run(id);
    f.sqlite.prepare(`UPDATE document_versions SET extraction_status='ready',page_count=1 WHERE id=?`).run(id);
  }
  return {...f,add,makeSent,ready};
}

describe("privacy-safe processing backlog audit",()=>{
  it("classifies pending, overdue, exhausted, rejected, closed, completed and inconsistent jobs",async()=>{
    const f=fixture();
    try{
      f.add("p_fresh","2026-11-18 17:25:00");
      f.add("p_old","2026-11-18 16:00:00");
      f.add("in_flight","2026-11-18 17:00:00");
      f.makeSent("in_flight",1,"2026-11-18T17:28:00.000Z");
      f.add("retry_due","2026-11-18 16:30:00");
      f.makeSent("retry_due",2,"2026-11-18T16:50:00.000Z");
      f.add("maxed","2026-11-18 14:00:00");
      f.makeSent("maxed",10,"2026-11-18T14:40:00.000Z");
      f.add("rejected","2026-11-18 14:00:00");
      f.makeSent("rejected",1,"2026-11-18T14:30:00.000Z");
      f.sqlite.exec("UPDATE document_versions SET extraction_status='needs_review' WHERE id='rejected'");
      f.add("paused","2026-11-18 14:00:00","c_closed");
      f.add("done","2026-11-18 14:00:00");
      f.ready("done");
      f.add("bad_state","2026-11-18 14:00:00");
      f.makeSent("bad_state",0,null);
      const result=await auditProcessingBacklog(f.db,{now:NOW});
      expect(result).toMatchObject({
        complete:true,scanned:9,untrackedPending:0,
        pendingFresh:1,pendingOverdue:1,inFlight:1,retryDue:1,exhausted:1,
        rejected:1,paused:1,completed:1,inconsistent:1,needsAttention:true
      });
      const serialized=JSON.stringify(result);
      expect(serialized).not.toContain("PRIVATE_");
      expect(serialized).not.toContain("c_active");
      expect(serialized).not.toContain("doc_rejected");
      expect(serialized).not.toContain("a".repeat(64));
    }finally{f.close();}
  });

  it("reports incomplete rather than presenting truncated rows as complete",async()=>{
    const f=fixture();
    try {
      for(let n=0;n<4;n++)f.add("p_"+n,"2026-11-18 16:00:00");
      const report=await auditProcessingBacklog(f.db,{now:NOW,maxRows:2});
      expect(report).toMatchObject({complete:false,scanned:2,pendingOverdue:2,needsAttention:true});
      expect(report.pendingOverdue).not.toBe(4);
    }finally{f.close();}
  });

  it("detects pending documents whose outbox row is missing (without exposing IDs)",async()=>{
    const f=fixture();
    try{
      f.add("untracked","2026-11-18 16:00:00");
      // Simulates a previously corrupted/migrated database, not a supported write.
      f.sqlite.exec("DROP TRIGGER processing_outbox_no_delete");
      f.sqlite.exec("DELETE FROM document_processing_outbox WHERE document_version_id='untracked'");
      const result=await auditProcessingBacklog(f.db,{now:NOW});
      expect(result).toMatchObject({scanned:0,untrackedPending:1,needsAttention:true});
      expect(JSON.stringify(result)).not.toContain("doc_untracked");
    }finally{f.close();}
  });

  it("rejects invalid limits and clocks without scanning the database",async()=>{
    const f=fixture();
    try {
      await expect(auditProcessingBacklog(f.db,{maxRows:0})).rejects.toThrow();
      await expect(auditProcessingBacklog(f.db,{maxRows:2001})).rejects.toThrow();
      await expect(auditProcessingBacklog(f.db,{now:new Date(NaN)})).rejects.toThrow();
    }finally{f.close();}
  });

  it("classifies future and malformed times as inconsistent, not as safe in-flight work",async()=>{
    const f=fixture();
    try {
      f.add("future","2026-11-18 17:00:00");
      f.makeSent("future",1,"2028-11-18T00:00:00.000Z");
      f.add("nonsense","2026-11-18 17:00:00");
      f.makeSent("nonsense",1,"2026-02-30T12:00:00.000Z");
      const result=await auditProcessingBacklog(f.db,{now:NOW});
      expect(result).toMatchObject({scanned:2,inconsistent:2,inFlight:0,retryDue:0});
    }finally{f.close();}
  });
});
