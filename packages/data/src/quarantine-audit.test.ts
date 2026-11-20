import { describe, expect, it, vi } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDocumentUpload } from "./documents";
import { auditQuarantine, type QuarantineAuditOptions } from "./quarantine-audit";

// SQLite creates rows at the host clock; keep the synthetic audit clock far
// enough ahead that its 48h cutoff never excludes rows just inserted by D1.
const NOW = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
const old = new Date(NOW.getTime() - 8 * 24 * 60 * 60 * 1000);
const recent = new Date(NOW.getTime() - 60 * 60 * 1000);
const DOC_KEY = "quarantine/11111111-1111-4111-8111-111111111111.pdf";
const ORPHAN_KEY = "quarantine/22222222-2222-4222-8222-222222222222.pdf";
const PENDING_KEY = "quarantine/33333333-3333-4333-8333-333333333333.pdf";
const CHECKSUM = "a".repeat(64);
const defaults: QuarantineAuditOptions = { now: NOW, maxPages: 3, pageSize: 2, maxReferences: 10 };

function fixture() {
  const f = makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name) VALUES ('c_a','A');
    INSERT INTO commission_members(commission_id,subject,role) VALUES ('c_a','alice','member');
    INSERT INTO document_batches(id,commission_id,label) VALUES ('b_a','c_a','Obras');
  `);
  const objects = new Map<string, { uploaded: Date; sha256?: string }>();
  const calls: string[] = [];
  const list = vi.fn(async ({prefix,limit,cursor}:{prefix:string;limit:number;cursor?:string}) => {
    calls.push("list");
    const keys = [...objects.keys()].filter(key=>key.startsWith(prefix)).sort();
    const start = cursor === undefined ? 0 : Number(cursor);
    const selected = keys.slice(start,start+limit);
    return {
      objects: selected.map(key=>({
        key, uploaded:objects.get(key)!.uploaded,
        customMetadata:objects.get(key)!.sha256 ? {sha256:objects.get(key)!.sha256} : {}
      })),
      truncated:start+limit<keys.length,
      cursor:start+limit<keys.length ? String(start+limit):undefined
    };
  });
  const head = vi.fn(async (key:string)=>{
    calls.push("head");
    const found=objects.get(key);
    return found ? {key,uploaded:found.uploaded,customMetadata:{sha256:found.sha256}} : null;
  });
  const del = vi.fn(async(_key:string)=>{ throw Error("Deletion is not supported by the auditor"); });
  const bucket = {list,head,delete:del} as unknown as R2Bucket;
  async function addDocument(key=DOC_KEY,hash=CHECKSUM) {
    await persistDocumentUpload(f.db,{
      commissionId:"c_a",batchId:"b_a",subject:"alice",
      documentId:"doc_a",versionId:"v_a",sha256:hash,r2Key:key,
      filename:"obra.pdf",idempotencyKey:"upload_unique_101"
    });
  }
  return {...f, objects,calls,bucket,list,head,del,addDocument};
}

describe("non-destructive quarantine reconciliation",()=>{
  it("recognizes a referenced object without exposing its key or reading PDF bytes",async()=>{
    const f=fixture();
    try {
      await f.addDocument();
      f.objects.set(DOC_KEY,{uploaded:old,sha256:CHECKSUM});
      const result=await auditQuarantine(f.db,f.bucket,defaults);
      expect(result.complete).toBe(true);
      expect(result.referenced).toBe(1);
      expect(result.orphanCandidates).toBe(0);
      expect(result.missingObjects).toBe(0);
      expect(result.findings).toEqual([]);
      expect(f.del).not.toHaveBeenCalled();
      expect(f.calls).not.toContain("get");
    }finally{f.close();}
  });

  it("reports only aged unreferenced candidates and ignores recent uploads in the grace window",async()=>{
    const f=fixture();
    try {
      f.objects.set(ORPHAN_KEY,{uploaded:old});
      f.objects.set(PENDING_KEY,{uploaded:recent});
      const result=await auditQuarantine(f.db,f.bucket,defaults);
      expect(result.orphanCandidates).toBe(1);
      expect(result.recentUnreferenced).toBe(1);
      expect(result.findings).toEqual([expect.objectContaining({kind:"orphan_candidate"})]);
      expect(JSON.stringify(result)).not.toContain(ORPHAN_KEY);
      expect(JSON.stringify(result)).not.toContain(PENDING_KEY);
      expect(result.findings[0]?.keyFingerprint).toMatch(/^[a-f0-9]{24}$/);
      expect(f.del).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("detects a D1 reference whose R2 object has disappeared",async()=>{
    const f=fixture();
    try {
      await f.addDocument();
      const result=await auditQuarantine(f.db,f.bucket,defaults);
      expect(result.missingObjects).toBe(1);
      expect(result.findings).toMatchObject([{kind:"missing_referenced_object"}]);
      expect(JSON.stringify(result)).not.toContain(DOC_KEY);
    }finally{f.close();}
  });

  it("flags SHA-256 metadata mismatches but never calls that a physical hash verification",async()=>{
    const f=fixture();
    try {
      await f.addDocument();
      f.objects.set(DOC_KEY,{uploaded:old,sha256:"b".repeat(64)});
      const result=await auditQuarantine(f.db,f.bucket,defaults);
      expect(result.metadataMismatches).toBe(1);
      expect(result.findings).toMatchObject([{kind:"metadata_mismatch"}]);
      expect(result.integrityVerified).toBe(false);
    }finally{f.close();}
  });

  it("follows R2 cursors and refuses to imply complete coverage when capped",async()=>{
    const f=fixture();
    try {
      for(let i=0;i<5;i++) f.objects.set(`quarantine/${i}.pdf`,{uploaded:old});
      const partial=await auditQuarantine(f.db,f.bucket,{...defaults,maxPages:1,pageSize:2});
      expect(partial.complete).toBe(false);
      expect(partial.scannedR2).toBe(2);
      const full=await auditQuarantine(f.db,f.bucket,{...defaults,maxPages:3,pageSize:2});
      expect(full.complete).toBe(true);
      expect(full.scannedR2).toBe(5);
      expect(f.list).toHaveBeenCalledWith(expect.objectContaining({prefix:"quarantine/",limit:2}));
    }finally{f.close();}
  });

  it("bounds the diagnostic details without losing aggregate counts",async()=>{
    const f=fixture();
    try {
      for(let i=0;i<35;i++) f.objects.set(`quarantine/unlinked-${i}.pdf`,{uploaded:old});
      const report=await auditQuarantine(f.db,f.bucket,{
        ...defaults,maxPages:1,pageSize:100
      });
      expect(report.orphanCandidates).toBe(35);
      expect(report.findings).toHaveLength(25);
      expect(report.findingsTruncated).toBe(true);
      expect(report.complete).toBe(true);
      expect(f.del).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("refuses a grace period below 48 hours and invalid pagination",async()=>{
    const f=fixture();
    try {
      await expect(auditQuarantine(f.db,f.bucket,{...defaults,minAgeMs:60_000})).rejects.toThrow("48 hours");
      await expect(auditQuarantine(f.db,f.bucket,{...defaults,maxPages:100})).rejects.toThrow();
      expect(f.list).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("does not classify an object as an orphan when D1 is unavailable",async()=>{
    const f=fixture();
    try {
      f.objects.set(ORPHAN_KEY,{uploaded:old});
      f.sqlite.exec("DROP TABLE document_versions");
      await expect(auditQuarantine(f.db,f.bucket,defaults)).rejects.toThrow();
      expect(f.del).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("does not classify R2 head errors as missing objects",async()=>{
    const f=fixture();
    try {
      await f.addDocument();
      f.head.mockRejectedValueOnce(new Error("R2 read outage"));
      await expect(auditQuarantine(f.db,f.bucket,defaults)).rejects.toThrow("R2 read outage");
      expect(f.del).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("shows incomplete D1 coverage when the reference inspection cap is reached",async()=>{
    const f=fixture();
    try {
      await f.addDocument();
      f.sqlite.exec(`
        INSERT INTO documents(id,commission_id,batch_id,filename) VALUES ('doc_b','c_a','b_a','b.pdf');
        INSERT INTO document_versions(id,document_id,version_number,sha256,r2_object_key)
          VALUES('v_b','doc_b',1,'${CHECKSUM}','${ORPHAN_KEY}');
      `);
      f.objects.set(DOC_KEY,{uploaded:old,sha256:CHECKSUM});
      f.objects.set(ORPHAN_KEY,{uploaded:old,sha256:CHECKSUM});
      const result=await auditQuarantine(f.db,f.bucket,{...defaults,maxReferences:1});
      expect(result.complete).toBe(false);
      expect(result.scannedD1).toBe(1);
      expect(result.referenced).toBe(2);
    }finally{f.close();}
  });
});
