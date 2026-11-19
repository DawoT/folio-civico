/**
 * Signed admission boundary for text produced by a separate PDF inspection
 * service. This module NEVER parses or serves the untrusted PDF itself.
 * No public endpoint invokes publishInspectedText. The inspector, credentials,
 * malware scanner and OCR engine are NOT deployed by this repository.
 */
export interface InspectedTextManifest {
  documentVersionId:string;
  sourceSha256:string;
  scanVerdict:"clean";
  scanner:string;
  scannerReportId:string;
  scannedAt:string;
  pages:Array<{page:number;text:string}>;
}
export interface DocumentTextView {
  versionId:string;
  sha256:string;
  pageCount:number;
  pages:Array<{page:number;text:string}>;
}
export class InspectionGateError extends Error {}

const MAX_ORIGINAL=8*1024*1024;
const MAX_PAGES=100;
const MAX_PAGE_TEXT=8000;
const hexDigest=(bytes:Uint8Array):string=>[...bytes].map(v=>v.toString(16).padStart(2,"0")).join("");
async function digest(input:Uint8Array):Promise<string> {
  return hexDigest(new Uint8Array(await crypto.subtle.digest("SHA-256",new Uint8Array(input).buffer)));
}
function strictObject(value:unknown,expected:string[]):value is Record<string,unknown> {
  return value!==null && typeof value==="object" && !Array.isArray(value)
    && Object.keys(value).length===expected.length
    && Object.keys(value).every(k=>expected.includes(k));
}
function validateManifest(input:InspectedTextManifest):void {
  if(!strictObject(input,["documentVersionId","sourceSha256","scanVerdict","scanner","scannerReportId","scannedAt","pages"])) {
    throw new InspectionGateError("Unexpected inspection manifest fields");
  }
  if(!/^[A-Za-z0-9_-]{1,64}$/.test(input.documentVersionId)
    || !/^[a-f0-9]{64}$/.test(input.sourceSha256)
    || input.scanVerdict!=="clean"
    || !/^[A-Za-z0-9._-]{3,80}$/.test(input.scanner)
    || !/^[A-Za-z0-9_-]{8,96}$/.test(input.scannerReportId)
    || !Number.isFinite(Date.parse(input.scannedAt))
    || new Date(input.scannedAt).toISOString()!==input.scannedAt
    || !Array.isArray(input.pages) || input.pages.length<1 || input.pages.length>MAX_PAGES) {
    throw new InspectionGateError("Invalid or non-clean inspection manifest");
  }
  for(const [index,page] of input.pages.entries()) {
    if(!strictObject(page,["page","text"]) || page.page!==index+1
      || typeof page.text!=="string" || !page.text.trim()
      || page.text.length>MAX_PAGE_TEXT
      || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(page.text)) {
      throw new InspectionGateError("Incomplete, ambiguous or oversized page extraction");
    }
  }
}

/**
 * Deterministic UTF-8 JSON message for an external inspector's HMAC.
 * Its exact property order is part of the v1 protocol contract.
 */
export function serializeInspectionManifest(input:InspectedTextManifest):Uint8Array {
  validateManifest(input);
  const ordered={
    documentVersionId:input.documentVersionId,
    sourceSha256:input.sourceSha256,
    scanVerdict:input.scanVerdict,
    scanner:input.scanner,
    scannerReportId:input.scannerReportId,
    scannedAt:input.scannedAt,
    pages:input.pages.map(p=>({page:p.page,text:p.text}))
  };
  return new TextEncoder().encode(JSON.stringify(ordered));
}
async function verifySignature(data:Uint8Array,signature:string,secret:string):Promise<boolean> {
  if(!/^[a-f0-9]{64}$/.test(signature) || secret.length<32) return false;
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),
    {name:"HMAC",hash:"SHA-256"},false,["verify"]);
  const sig=new Uint8Array(signature.match(/../g)!.map(v=>parseInt(v,16)));
  return crypto.subtle.verify("HMAC",key,new Uint8Array(sig).buffer,new Uint8Array(data).buffer);
}

type OriginalRow={
  id:string; sha256:string; r2Key:string; extractionStatus:string; commissionStatus:string;
};
type PriorReport={manifestSha256:string};
type PageRow={page:number;text:string};
export async function publishInspectedText(
  db:D1Database,bucket:R2Bucket,input:InspectedTextManifest,signature:string,
  inspectorSecret:string
):Promise<{documentVersionId:string;pageCount:number;repeated:boolean}> {
  const serialized=serializeInspectionManifest(input);
  if(!(await verifySignature(serialized,signature,inspectorSecret))) {
    throw new InspectionGateError("Inspection signature could not be verified");
  }
  const manifestSha256=await digest(serialized);
  const original=await db.prepare(`
    SELECT v.id,v.sha256,v.r2_object_key AS r2Key,
      v.extraction_status AS extractionStatus,c.status AS commissionStatus
    FROM document_versions v
    JOIN documents d ON d.id=v.document_id
    JOIN commissions c ON c.id=d.commission_id
    WHERE v.id=?
  `).bind(input.documentVersionId).first<OriginalRow>();
  if(!original || original.sha256!==input.sourceSha256
    || !original.r2Key.startsWith("quarantine/")) {
    throw new InspectionGateError("Quarantined version and manifest do not match");
  }

  const checkPrior=async():Promise<{documentVersionId:string;pageCount:number;repeated:boolean}|null>=>{
    const prior=await db.prepare(`
      SELECT r.manifest_sha256 AS manifestSha256 FROM document_processing_reports r
      JOIN document_versions v ON v.id=r.document_version_id
      WHERE r.document_version_id=? AND v.extraction_status='ready'
    `).bind(input.documentVersionId).first<PriorReport>();
    if(!prior) return null;
    if(prior.manifestSha256!==manifestSha256) {
      throw new InspectionGateError("Version already processed with a different inspection");
    }
    return {documentVersionId:input.documentVersionId,pageCount:input.pages.length,repeated:true};
  };
  const prior=await checkPrior();
  if(prior) return prior;
  if(original.commissionStatus!=="active" || original.extractionStatus!=="pending") {
    throw new InspectionGateError("Version cannot enter inspected-text processing");
  }

  // Never run a PDF renderer, PDF script engine or unsafe parser in the API Worker.
  // Read only bytes to rehash the immutable original, with a strict bound.
  const stored=await bucket.get(original.r2Key);
  if(!stored) throw new InspectionGateError("Original R2 object missing");
  if(stored.size>MAX_ORIGINAL) throw new InspectionGateError("Original PDF exceeds processing cap");
  const bytes=new Uint8Array(await stored.arrayBuffer());
  if(bytes.byteLength===0 || bytes.byteLength>MAX_ORIGINAL
    || await digest(bytes)!==input.sourceSha256) {
    throw new InspectionGateError("Original R2 bytes fail integrity verification");
  }

  const statements=[
    db.prepare(`
      INSERT INTO document_processing_reports(
        document_version_id,scanner_name,scanner_report_id,scanned_at,
        source_sha256,manifest_sha256,page_count)
      SELECT v.id,?,?,?,?,?,? FROM document_versions v
      JOIN documents d ON d.id=v.document_id
      JOIN commissions c ON c.id=d.commission_id
      WHERE v.id=? AND v.sha256=? AND v.extraction_status='pending'
        AND v.r2_object_key LIKE 'quarantine/%' AND c.status='active'
    `).bind(input.scanner,input.scannerReportId,input.scannedAt,
      input.sourceSha256,manifestSha256,input.pages.length,
      input.documentVersionId,input.sourceSha256),
    ...input.pages.map(page=>db.prepare(`
      INSERT INTO document_pages(document_version_id,page,extracted_text,extraction_status)
      SELECT v.id,?,?,'ready' FROM document_versions v
      JOIN document_processing_reports r ON r.document_version_id=v.id
      WHERE v.id=? AND r.manifest_sha256=? AND v.extraction_status='pending'
    `).bind(page.page,page.text,input.documentVersionId,manifestSha256)),
    db.prepare(`
      UPDATE document_versions SET extraction_status='ready',page_count=?
      WHERE id=? AND extraction_status='pending'
        AND EXISTS (SELECT 1 FROM document_processing_reports r
                    WHERE r.document_version_id=document_versions.id AND r.manifest_sha256=?)
    `).bind(input.pages.length,input.documentVersionId,manifestSha256),
    db.prepare(`
      INSERT INTO audit_events(id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json)
      SELECT ?,d.commission_id,?,'document.inspected_text_admitted','document_version',v.id,
        json_object('scanner',?,'reportId',?,'pages',?)
      FROM document_versions v JOIN documents d ON d.id=v.document_id
      WHERE v.id=? AND v.extraction_status='ready'
    `).bind(crypto.randomUUID(),"inspector:"+input.scanner,
      input.scanner,input.scannerReportId,input.pages.length,input.documentVersionId)
  ];
  try {
    const results=await db.batch(statements);
    if(results.some(x=>!x.success || x.meta.changes!==1)) {
      throw new InspectionGateError("Inspection was not admitted as one transaction");
    }
  }catch(error){
    // Concurrent identical arrivals must not produce duplicate pages or audit.
    const concurrent=await checkPrior();
    if(concurrent)return concurrent;
    if(error instanceof InspectionGateError)throw error;
    throw new InspectionGateError("Inspection transaction rejected");
  }
  return {documentVersionId:input.documentVersionId,pageCount:input.pages.length,repeated:false};
}

/** Same-origin browser API uses this only after a verified Access JWT. */
export async function getDocumentTextPages(
  db:D1Database,subject:string,commissionId:string,versionId:string
):Promise<DocumentTextView|null> {
  if(!subject || !commissionId || !versionId)return null;
  const metadata=await db.prepare(`
    SELECT v.sha256,v.page_count AS pageCount FROM document_versions v
    JOIN documents d ON d.id=v.document_id AND d.commission_id=?
    JOIN commission_members m ON m.commission_id=d.commission_id
      AND m.subject=? AND m.active=1
    JOIN document_processing_reports r ON r.document_version_id=v.id
      AND r.source_sha256=v.sha256 AND r.page_count=v.page_count
    WHERE v.id=? AND v.extraction_status='ready'
  `).bind(commissionId,subject,versionId).first<{sha256:string;pageCount:number}>();
  if(!metadata || metadata.pageCount<1 || metadata.pageCount>MAX_PAGES)return null;
  const result=await db.prepare(`
    SELECT p.page,p.extracted_text AS text
    FROM document_pages p
    JOIN document_versions v ON v.id=p.document_version_id
    JOIN documents d ON d.id=v.document_id
    JOIN commission_members m ON m.commission_id=d.commission_id
    WHERE d.commission_id=? AND m.subject=? AND m.active=1
      AND p.document_version_id=? AND v.extraction_status='ready'
      AND p.extraction_status='ready'
    ORDER BY p.page LIMIT ?
  `).bind(commissionId,subject,versionId,MAX_PAGES).all<PageRow>();
  const pages=result.results;
  if(pages.length!==metadata.pageCount || pages.some((item,i)=>item.page!==i+1
    || typeof item.text!=="string" || item.text.length>MAX_PAGE_TEXT))return null;
  return {versionId,sha256:metadata.sha256,pageCount:metadata.pageCount,pages};
}
