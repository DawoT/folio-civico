import {publishInspectedText,isProcessingRedriveAuthorized,verifyUnsafeInspectionVerdict,type UnsafeInspectionVerdict,type InspectedTextManifest,type ProcessingQueueMessage} from "@folio/data";

export interface ProcessorEnv {
  DB:D1Database;
  DOCUMENTS:R2Bucket;
  /** Service binding to an isolated, non-public scanner frontend. Not configured in Preview. */
  INSPECTOR?:Fetcher;
  /** Wrangler secrets, never vars or user-supplied values. */
  INSPECTOR_SERVICE_TOKEN?:string;
  INSPECTOR_HMAC_KEY?:string;
}
export type ProcessingResult="completed"|"already_done"|"stale"|"needs_review";
export interface BatchResult {acked:number; retried:number; invalid:number}
interface VersionStatus {
  sha256:string; r2Key:string; status:string; commissionStatus:string;
  commissionId:string;
}
const MAX_PDF_BYTES=8*1024*1024;
const MAX_RESULT_BYTES=2*1024*1024;
const QUEUE_NAME="folio-civico-pdf-pending";
const textEncoder=new TextEncoder();

export function parseProcessingMessage(raw:unknown):ProcessingQueueMessage|null {
  if(!raw || typeof raw!=="object" || Array.isArray(raw))return null;
  const obj=raw as Record<string,unknown>;
  const hasManual=Object.hasOwn(obj,"manualRedriveId");
  if(Object.keys(obj).length!==(hasManual?4:3)
    || (hasManual && (typeof obj.manualRedriveId!=="string"
      || !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(obj.manualRedriveId)))
    || obj.kind!=="folio.process.pdf"
    || typeof obj.versionId!=="string"
    || !/^[A-Za-z0-9_-]{1,64}$/.test(obj.versionId)
    || typeof obj.sourceSha256!=="string"
    || !/^[a-f0-9]{64}$/.test(obj.sourceSha256)) return null;
  return {kind:"folio.process.pdf",versionId:obj.versionId,sourceSha256:obj.sourceSha256,
    ...(hasManual?{manualRedriveId:obj.manualRedriveId as string}:{})};
}
async function digest(original:Uint8Array):Promise<string> {
  const hash=await crypto.subtle.digest("SHA-256",new Uint8Array(original).buffer);
  return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function boundedJson(response:Response):Promise<unknown> {
  const len=response.headers.get("content-length");
  if(len && (!/^\d+$/.test(len) || Number(len)>MAX_RESULT_BYTES)) {
    throw new Error("Inspector response too large");
  }
  if(!response.body)throw new Error("Inspector returned no report");
  const reader=response.body.getReader();
  const chunks:Uint8Array[]=[];
  let size=0;
  try{
    while(true){
      const part=await reader.read();
      if(part.done)break;
      size+=part.value.byteLength;
      if(size>MAX_RESULT_BYTES){
        await reader.cancel("Inspector result size");
        throw new Error("Inspector result exceeds limit");
      }
      chunks.push(part.value);
    }
  }finally{reader.releaseLock();}
  const buffer=new Uint8Array(size);
  let pos=0;
  for(const chunk of chunks){buffer.set(chunk,pos);pos+=chunk.byteLength;}
  try{return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(buffer)) as unknown;}
  catch{throw new Error("Malformed inspection result");}
}
function reportResponse(raw:unknown):{manifest:InspectedTextManifest;signature:string}{
  if(!raw || typeof raw!=="object" || Array.isArray(raw))throw new Error("Invalid inspection response");
  const obj=raw as Record<string,unknown>;
  if(Object.keys(obj).length!==2
    || typeof obj.signature!=="string"
    || !/^[a-f0-9]{64}$/.test(obj.signature)
    || !obj.manifest || typeof obj.manifest!=="object" || Array.isArray(obj.manifest)) {
    throw new Error("Invalid inspection response");
  }
  return {manifest:obj.manifest as InspectedTextManifest,signature:obj.signature};
}
/**
 * Cross-request commission closure can occur while reading private R2 or
 * awaiting the inspector. Recheck before disclosing bytes and before writes.
 * SQL triggers independently protect the final D1 transaction.
 */
async function isActivePendingVersion(
 db:D1Database,versionId:string,sourceSha256:string
):Promise<boolean>{
 const row=await db.prepare(`
  SELECT 1 AS allowed FROM document_versions v
  JOIN documents d ON d.id=v.document_id
  JOIN commissions c ON c.id=d.commission_id
  WHERE v.id=? AND v.sha256=? AND v.extraction_status='pending'
    AND c.status='active'
 `).bind(versionId,sourceSha256).first<{allowed:number}>();
 return row!==null;
}
async function recordUnsafeInspection(db:D1Database,versionId:string,commissionId:string):Promise<void>{
  const result=await db.batch([
    db.prepare(`
      UPDATE document_versions SET extraction_status='needs_review'
      WHERE id=? AND extraction_status='pending'
        AND EXISTS (
          SELECT 1 FROM documents d
          JOIN commissions c ON c.id=d.commission_id
          WHERE d.id=document_versions.document_id
            AND c.id=? AND c.status='active'
        )
    `).bind(versionId,commissionId),
    // Audit only the preceding UPDATE's actual transition within D1.batch.
    // A concurrent winning 422 must not generate two rejection events.
    db.prepare(`
      INSERT INTO audit_events(id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json)
      SELECT ?,d.commission_id,'inspector:isolated','document.inspection_rejected','document_version',v.id,
        json_object('result','needs_review')
      FROM document_versions v
      JOIN documents d ON d.id=v.document_id
      JOIN commissions c ON c.id=d.commission_id
      WHERE v.id=? AND v.extraction_status='needs_review'
        AND c.id=? AND c.status='active' AND changes()=1
    `).bind(crypto.randomUUID(),versionId,commissionId)
  ]);
  if(result.some(item=>!item.success || item.meta.changes!==1)){
    throw new Error("Unsafe inspection state update rejected");
  }
}
export async function processProcessingMessage(
  raw:ProcessingQueueMessage,env:ProcessorEnv
):Promise<ProcessingResult>{
  const message=parseProcessingMessage(raw);
  if(!message)throw new Error("Invalid queue message");
  // A manual one-shot must be bound to its immutable D1 reservation. The
  // check is also needed for ordinary messages to prevent stripping the tag.
  if(!await isProcessingRedriveAuthorized(
    env.DB,message.versionId,message.sourceSha256,message.manualRedriveId
  ))return "stale";
  const version=await env.DB.prepare(`
    SELECT v.sha256,v.r2_object_key AS r2Key,v.extraction_status AS status,
      d.commission_id AS commissionId,c.status AS commissionStatus
    FROM document_versions v JOIN documents d ON d.id=v.document_id
    JOIN commissions c ON c.id=d.commission_id
    WHERE v.id=?
  `).bind(message.versionId).first<VersionStatus>();
  if(!version || version.sha256!==message.sourceSha256
    || version.commissionStatus!=="active")return "stale";
  if(version.status==="ready")return "already_done";
  if(version.status!=="pending")return "stale";
  if(!env.INSPECTOR || !env.INSPECTOR_HMAC_KEY || env.INSPECTOR_HMAC_KEY.length<32
    || !env.INSPECTOR_SERVICE_TOKEN || env.INSPECTOR_SERVICE_TOKEN.length<32) {
    throw new Error("Isolated inspector service or credentials not configured");
  }
  if(!version.r2Key.startsWith("quarantine/"))throw new Error("Version does not reference private quarantine");
  const original=await env.DOCUMENTS.get(version.r2Key);
  if(!original || original.size>MAX_PDF_BYTES)throw new Error("Original missing or exceeds limit");
  const originalBytes=new Uint8Array(await original.arrayBuffer());
  if(!originalBytes.length || originalBytes.length>MAX_PDF_BYTES
    || await digest(originalBytes)!==message.sourceSha256) {
    throw new Error("Original PDF failed integrity");
  }
  // Avoid handing the original to the scanner if the authorization was
  // invalidated during the potentially slow private R2 read and digest.
  if(!await isProcessingRedriveAuthorized(
    env.DB,message.versionId,message.sourceSha256,message.manualRedriveId
  ))return "stale";
  if(!await isActivePendingVersion(env.DB,message.versionId,message.sourceSha256))return "stale";
  // Service binding only: an operator-deployed and isolated inspection service.
  // No arbitrary URL from messages, credentials, hostnames or D1 records.
  const requestNonce=crypto.randomUUID().replaceAll("-","");
  const response=await env.INSPECTOR.fetch(new Request("https://inspector.internal/inspect",{
    method:"POST",
    headers:{
      "Content-Type":"application/pdf",
      "X-Folio-Document-Version":message.versionId,
      "X-Folio-Source-Sha256":message.sourceSha256,
      "X-Folio-Inspection-Nonce":requestNonce,
      "X-Folio-Inspector-Token":env.INSPECTOR_SERVICE_TOKEN
    },
    body:originalBytes as BodyInit
  }));
  if(response.status===422){
    // 422 alone is not a terminal document verdict: require gateway HMAC,
    // version, original SHA and a fresh challenge bound to THIS request.
    // Unsigned, replayed or mismatched responses are retried, not persisted.
    if(!response.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")){
      throw new Error("Unsigned unsafe inspection verdict");
    }
    const raw=await boundedJson(response);
    if(!raw || typeof raw!=="object" || Array.isArray(raw)
      || Object.keys(raw).length!==2 || !("verdict" in raw)
      || !("signature" in raw) || typeof raw.signature!=="string"){
      throw new Error("Invalid unsafe inspection verdict");
    }
    const verdict=raw.verdict as UnsafeInspectionVerdict;
    if(!verdict || typeof verdict!=="object" || Array.isArray(verdict)
      || verdict.documentVersionId!==message.versionId
      || verdict.sourceSha256!==message.sourceSha256
      || verdict.requestNonce!==requestNonce
      || !await verifyUnsafeInspectionVerdict(
        verdict,raw.signature,env.INSPECTOR_HMAC_KEY
      )){
      throw new Error("Invalid signed unsafe inspection verdict");
    }
    if(!await isProcessingRedriveAuthorized(
      env.DB,message.versionId,message.sourceSha256,message.manualRedriveId
    ))return "stale";
    if(!await isActivePendingVersion(env.DB,message.versionId,message.sourceSha256))return "stale";
    try {
      await recordUnsafeInspection(env.DB,message.versionId,version.commissionId);
    }catch(error){
      if(!await isProcessingRedriveAuthorized(
        env.DB,message.versionId,message.sourceSha256,message.manualRedriveId
      ))return "stale";
      if(!await isActivePendingVersion(env.DB,message.versionId,message.sourceSha256))return "stale";
      throw error;
    }
    return "needs_review";
  }
  if(!response.ok)throw new Error("Inspector unavailable or failed");
  const {manifest,signature}=reportResponse(await boundedJson(response));
  if(manifest.documentVersionId!==message.versionId || manifest.sourceSha256!==message.sourceSha256){
    throw new Error("Inspector report refers to another original");
  }
  // The external inspection may be slow: revalidate immediately before
  // publishing. D1 triggers still defend the subsequent check/write race.
  if(!await isProcessingRedriveAuthorized(
    env.DB,message.versionId,message.sourceSha256,message.manualRedriveId
  ))return "stale";
  if(!await isActivePendingVersion(env.DB,message.versionId,message.sourceSha256))return "stale";
  try {
    const result=await publishInspectedText(
      env.DB,env.DOCUMENTS,manifest,signature,env.INSPECTOR_HMAC_KEY
    );
    return result.repeated?"already_done":"completed";
  }catch(error){
    if(!await isProcessingRedriveAuthorized(
      env.DB,message.versionId,message.sourceSha256,message.manualRedriveId
    ))return "stale";
    if(!await isActivePendingVersion(env.DB,message.versionId,message.sourceSha256))return "stale";
    throw error;
  }
}

export async function processBatch(
  batch:MessageBatch<unknown>,env:ProcessorEnv
):Promise<BatchResult>{
  if(batch.queue!==QUEUE_NAME)throw new Error("Unexpected queue source");
  const stats:BatchResult={acked:0,retried:0,invalid:0};
  for(const item of batch.messages){
    const parsed=parseProcessingMessage(item.body);
    if(!parsed){
      // Invalid messages never get access to R2, D1 or inspector. Never log body.
      item.ack();
      stats.invalid++;
      continue;
    }
    try{
      await processProcessingMessage(parsed,env);
      item.ack();
      stats.acked++;
    }catch{
      // Retry transient or unverified processing without logging document content.
      // Operator must configure a DLQ, max_retries and alerting before deployment.
      item.retry();
      stats.retried++;
    }
  }
  return stats;
}
