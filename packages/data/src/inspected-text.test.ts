import { describe,expect,it,vi } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDocumentUpload } from "./documents";
import { publishInspectedText, getDocumentTextPages, type InspectedTextManifest } from "./inspected-text";

const testSigningKey="synthetic".repeat(6);
const pdf=new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");

async function digest(input:Uint8Array):Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256",new Uint8Array(input).buffer))].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function sign(manifest:InspectedTextManifest):Promise<string> {
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(testSigningKey),
    {name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const result=await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(JSON.stringify(manifest)));
  return [...new Uint8Array(result)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function fixture() {
  const f=makeD1();
  const sha=await digest(pdf);
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('c_a','A','active'),('c_b','B','active');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES('c_a','alice','member',1),('c_a','observer','observer',1),('c_b','bob','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Obras'),('b_b','c_b','Other');
  `);
  const key="quarantine/7d148c61-6da2-4b56-8df0-c7d17ef338a4.pdf";
  await persistDocumentUpload(f.db,{
    commissionId:"c_a",batchId:"b_a",subject:"alice",documentId:"doc_a",versionId:"ver_a",
    sha256:sha,r2Key:key,filename:"obra.pdf",idempotencyKey:"upload_scanned_001"
  });
  const get=vi.fn(async (path:string)=>{
    if(path!==key)return null;
    return {arrayBuffer:async()=>pdf.buffer.slice(pdf.byteOffset,pdf.byteOffset+pdf.byteLength),
      customMetadata:{sha256:sha}};
  });
  const bucket={get} as unknown as R2Bucket;
  const manifest:InspectedTextManifest={
    documentVersionId:"ver_a",sourceSha256:sha,scanVerdict:"clean",
    scanner:"isolated-inspector-v1",scannerReportId:"scan_test_12345",
    scannedAt:"2026-11-18T17:30:00.000Z",
    pages:[{page:1,text:"Expediente de obra — página uno"},{page:2,text:"Sección de contrataciones"}]
  };
  return {...f,sha,key,bucket,get,manifest};
}

describe("signed, fail-closed document text admission",()=>{
  it("accepts a signed clean manifest only after checking the actual R2 original digest",async()=>{
    const f=await fixture();
    try {
      const result=await publishInspectedText(f.db,f.bucket,f.manifest,await sign(f.manifest),testSigningKey);
      expect(result).toMatchObject({documentVersionId:"ver_a",pageCount:2,repeated:false});
      expect(f.get).toHaveBeenCalledWith(f.key);
      expect(f.sqlite.prepare("SELECT extraction_status,page_count FROM document_versions WHERE id='ver_a'").get())
        .toMatchObject({extraction_status:"ready",page_count:2});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages WHERE document_version_id='ver_a'").get())
        .toMatchObject({n:2});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:2});
    }finally{f.close();}
  });
  it("uses deterministic HMAC message bytes irrespective of object property insertion order",async()=>{
    const f=await fixture();
    try {
      const reversed:InspectedTextManifest={
        pages:f.manifest.pages,
        scannedAt:f.manifest.scannedAt,scannerReportId:f.manifest.scannerReportId,
        scanner:f.manifest.scanner,scanVerdict:"clean",
        sourceSha256:f.manifest.sourceSha256,documentVersionId:f.manifest.documentVersionId
      };
      const signature=await sign(f.manifest);
      const output=await publishInspectedText(f.db,f.bucket,reversed,signature,testSigningKey);
      expect(output.repeated).toBe(false);
      expect(output.pageCount).toBe(2);
    }finally{f.close();}
  });

  it("rejects an oversized R2 original before loading its contents",async()=>{
    const f=await fixture();
    try {
      const oversizedBuffer=vi.fn(async()=>pdf.buffer);
      (f.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        size:9*1024*1024,arrayBuffer:oversizedBuffer
      });
      await expect(publishInspectedText(f.db,f.bucket,f.manifest,
        await sign(f.manifest),testSigningKey)).rejects.toThrow(/exceeds processing cap/);
      expect(oversizedBuffer).not.toHaveBeenCalled();
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get()).toMatchObject({n:0});
    }finally{f.close();}
  });

  it("does not duplicate report, pages or audit on an identical retry",async()=>{
    const f=await fixture();
    try {
      const signature=await sign(f.manifest);
      await publishInspectedText(f.db,f.bucket,f.manifest,signature,testSigningKey);
      const replay=await publishInspectedText(f.db,f.bucket,f.manifest,signature,testSigningKey);
      expect(replay.repeated).toBe(true);
      expect(f.get).toHaveBeenCalledTimes(1);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:2});
      const different={...f.manifest,pages:[{page:1,text:"Otros datos"}]};
      await expect(publishInspectedText(f.db,f.bucket,different,await sign(different),testSigningKey)).rejects.toThrow();
    }finally{f.close();}
  });
  it("rejects forged signatures, unsafe verdicts, inconsistent hashes and altered source bytes",async()=>{
    const f=await fixture();
    try {
      await expect(publishInspectedText(f.db,f.bucket,f.manifest,"0".repeat(64),testSigningKey)).rejects.toThrow();
      const unsafe={...f.manifest,scanVerdict:"infected" as const} as unknown as InspectedTextManifest;
      await expect(publishInspectedText(f.db,f.bucket,unsafe,await sign(unsafe),testSigningKey)).rejects.toThrow();
      const wrongHash={...f.manifest,sourceSha256:"f".repeat(64)};
      await expect(publishInspectedText(f.db,f.bucket,wrongHash,await sign(wrongHash),testSigningKey)).rejects.toThrow();
      const altered=new TextEncoder().encode("%PDF-1.7\nTAMPERED");
      (f.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        arrayBuffer:async()=>altered.buffer.slice(altered.byteOffset,altered.byteOffset+altered.byteLength)
      });
      await expect(publishInspectedText(f.db,f.bucket,f.manifest,await sign(f.manifest),testSigningKey)).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='ver_a'").get())
        .toMatchObject({extraction_status:"pending"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
  it("rejects incomplete or oversized page manifests, and never publishes partial pages",async()=>{
    const f=await fixture();
    try {
      for(const pages of [
        [{page:2,text:"Starts at second page"}],
        [{page:1,text:"A"},{page:3,text:"Skipped second"}],
        [{page:1,text:"X".repeat(9000)}],
        []
      ]) {
        const altered={...f.manifest,pages};
        await expect(publishInspectedText(f.db,f.bucket,altered,await sign(altered),testSigningKey)).rejects.toThrow();
      }
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
  it("keeps page text private to active members and excludes R2 keys",async()=>{
    const f=await fixture();
    try {
      await expect(getDocumentTextPages(f.db,"alice","c_a","ver_a")).resolves.toBeNull();
      await publishInspectedText(f.db,f.bucket,f.manifest,await sign(f.manifest),testSigningKey);
      const rows=await getDocumentTextPages(f.db,"alice","c_a","ver_a");
      expect(rows).toMatchObject({versionId:"ver_a",sha256:f.sha,pageCount:2});
      expect(rows?.pages[0]).toMatchObject({page:1,text:"Expediente de obra — página uno"});
      expect(JSON.stringify(rows)).not.toContain(f.key);
      expect(await getDocumentTextPages(f.db,"bob","c_a","ver_a")).toBeNull();
      expect(await getDocumentTextPages(f.db,"alice","c_b","ver_a")).toBeNull();
      expect(await getDocumentTextPages(f.db,"observer","c_a","ver_a")).not.toBeNull();
    }finally{f.close();}
  });
  it("locks source hash, original key and processed pages even after a status revocation",async()=>{
    const f=await fixture();
    try {
      await publishInspectedText(f.db,f.bucket,f.manifest,await sign(f.manifest),testSigningKey);
      expect(()=>f.sqlite.exec("UPDATE document_versions SET sha256='"+ "b".repeat(64) +"' WHERE id='ver_a'"))
        .toThrow(/INSPECTED_VERSION_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE document_versions SET r2_object_key='processed/fake.pdf' WHERE id='ver_a'"))
        .toThrow(/INSPECTED_VERSION_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE document_pages SET extracted_text='Falsificado' WHERE document_version_id='ver_a'"))
        .toThrow();
      expect(()=>f.sqlite.exec("UPDATE document_versions SET extraction_status='pending' WHERE id='ver_a'"))
        .toThrow(/CANNOT_REENTER_QUARANTINE/);
      f.sqlite.exec("UPDATE document_versions SET extraction_status='needs_review' WHERE id='ver_a'");
      expect(await getDocumentTextPages(f.db,"alice","c_a","ver_a")).toBeNull();
      expect(()=>f.sqlite.exec("DELETE FROM document_pages WHERE document_version_id='ver_a'"))
        .toThrow(/INSPECTED_PAGE_IMMUTABLE/);
    }finally{f.close();}
  });

  it("disallows direct ready-state writes without a verified inspector report",async()=>{
    const f=await fixture();
    try {
      expect(()=>f.sqlite.exec("UPDATE document_versions SET extraction_status='ready',page_count=2 WHERE id='ver_a'")).toThrow();
      expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='ver_a'").get())
        .toMatchObject({extraction_status:"pending"});
    }finally{f.close();}
  });
});
