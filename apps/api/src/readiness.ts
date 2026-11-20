/** This is storage readiness only. It cannot attest Cloudflare Queue or inspector health. */
export interface StorageReadinessEnv {
  DB?: D1Database;
  DOCUMENTS?: R2Bucket;
}

const HEADERS={
  "Cache-Control":"private, no-store, max-age=0",
  "X-Content-Type-Options":"nosniff",
  "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'"
} as const;

function response(body:object,status:number):Response {
  return Response.json(body,{status,headers:HEADERS});
}

/**
 * Only called after JWT verification and comparison to a dedicated operator
 * subject. Read-only probes never enqueue, alter D1, or inspect original PDFs.
 * A 200 here is NOT readiness for the document processing pipeline.
 */
export async function handleStorageReadiness(env:StorageReadinessEnv):Promise<Response>{
  if(!env.DB || !env.DOCUMENTS) {
    return response({status:"unavailable",scope:"api-storage"},503);
  }
  try{
    const probe=await env.DB.prepare("SELECT 1 AS heartbeat").first<{heartbeat:number}>();
    if(probe?.heartbeat!==1)throw new Error("D1 probe failed");
    const result=await env.DOCUMENTS.list({prefix:"quarantine/",limit:1});
    if(!result || !Array.isArray(result.objects) || typeof result.truncated!=="boolean") {
      throw new Error("R2 list probe failed");
    }
    // Never expose object metadata, storage paths, commission IDs or secrets.
    return response({status:"ready",scope:"api-storage",documentPipeline:"not_verified"},200);
  }catch{
    return response({status:"unavailable",scope:"api-storage"},503);
  }
}
