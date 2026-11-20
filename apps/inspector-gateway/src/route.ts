import {serializeInspectionManifest,serializeUnsafeInspectionVerdict,type InspectedTextManifest,type UnsafeInspectionVerdict} from "@folio/data";

/**
 * Fail-closed service-binding gateway between the PDF Queue Worker and a
 * Cloudflare Container. Pure request handler, tested without container access.
 *
 * No public hostname, no user-controlled destination, no raw PDF responses.
 */
export interface InspectorGatewaySecrets {
  INSPECTOR_SERVICE_TOKEN?: string;
  INSPECTOR_HMAC_KEY?: string;
}
export type InspectorContainerForwarder = (request:Request)=>Promise<Response>;
const MAX_PDF_BYTES=8*1024*1024;
const MAX_REPORT_BYTES=2*1024*1024;
const RESPONSE_HEADERS={
  "Cache-Control":"private, no-store, max-age=0",
  "X-Content-Type-Options":"nosniff",
  "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'"
} as const;
function empty(status:number):Response {return new Response(null,{status,headers:RESPONSE_HEADERS});}
function secureEqual(left:string,right:string):boolean{
  const max=Math.max(left.length,right.length);
  let mismatch=left.length^right.length;
  for(let i=0;i<max;i++)mismatch|=(left.charCodeAt(i)||0)^(right.charCodeAt(i)||0);
  return mismatch===0;
}
async function readBounded(body:ReadableStream<Uint8Array>|null,limit:number):Promise<Uint8Array>{
  if(!body)throw new RangeError("Missing request body");
  const reader=body.getReader(),chunks:Uint8Array[]=[];
  let size=0;
  try{
    while(true){
      const part=await reader.read();
      if(part.done)break;
      size+=part.value.byteLength;
      if(size>limit) {
        await reader.cancel("Size cap");
        throw new RangeError("Body exceeds size cap");
      }
      chunks.push(part.value);
    }
  }finally{reader.releaseLock();}
  const buffer=new Uint8Array(size);
  let offset=0;
  for(const chunk of chunks){buffer.set(chunk,offset);offset+=chunk.byteLength;}
  return buffer;
}
async function signCanonical(data:Uint8Array,secret:string):Promise<string>{
  const key=await crypto.subtle.importKey(
    "raw",new TextEncoder().encode(secret),
    {name:"HMAC",hash:"SHA-256"},false,["sign"]
  );
  const mac=new Uint8Array(await crypto.subtle.sign(
    "HMAC",key,new Uint8Array(data).buffer
  ));
  return Array.from(mac,n=>n.toString(16).padStart(2,"0")).join("");
}
async function signedUnsafeResponse(
  documentVersionId:string,sourceSha256:string,requestNonce:string,secret:string
):Promise<Response>{
  const verdict:UnsafeInspectionVerdict={
    kind:"folio.inspection.unsafe.v1",documentVersionId,sourceSha256,requestNonce
  };
  const signature=await signCanonical(serializeUnsafeInspectionVerdict(verdict),secret);
  return new Response(JSON.stringify({verdict,signature}),{
    status:422,headers:{...RESPONSE_HEADERS,"Content-Type":"application/json; charset=utf-8"}
  });
}
async function sha256(input:Uint8Array):Promise<string>{
  const hash=await crypto.subtle.digest("SHA-256",new Uint8Array(input).buffer);
  return Array.from(new Uint8Array(hash),n=>n.toString(16).padStart(2,"0")).join("");
}
export async function handleInspectorGatewayRequest(
  request:Request,secrets:InspectorGatewaySecrets,forward:InspectorContainerForwarder
):Promise<Response>{
  const path=new URL(request.url);
  if(path.pathname!=="/inspect" || path.search)return empty(404);
  if(request.method!=="POST")return empty(405);
  if(!secrets.INSPECTOR_SERVICE_TOKEN || secrets.INSPECTOR_SERVICE_TOKEN.length<32
    || secrets.INSPECTOR_SERVICE_TOKEN.length>256
    || !secrets.INSPECTOR_HMAC_KEY || secrets.INSPECTOR_HMAC_KEY.length<32)return empty(503);

  const token=request.headers.get("X-Folio-Inspector-Token")??"";
  if(!secureEqual(token,secrets.INSPECTOR_SERVICE_TOKEN))return empty(403);
  if(request.headers.has("Origin"))return empty(403);
  const version=request.headers.get("X-Folio-Document-Version")??"";
  const expectedHash=request.headers.get("X-Folio-Source-Sha256")??"";
  const requestNonce=request.headers.get("X-Folio-Inspection-Nonce")??"";
  if(!/^[A-Za-z0-9_-]{1,64}$/.test(version) || !/^[a-f0-9]{64}$/.test(expectedHash)
    || !/^[a-f0-9]{32}$/.test(requestNonce)
    || request.headers.get("Content-Type")!=="application/pdf")return empty(400);
  const declared=request.headers.get("Content-Length");
  if(declared && (!/^\d+$/.test(declared)||Number(declared)>MAX_PDF_BYTES))return empty(413);
  let original:Uint8Array;
  try{original=await readBounded(request.body,MAX_PDF_BYTES);}
  catch{return empty(413);}
  if(original.length<12)return empty(400);
  // A hash mismatch indicates a broken transport/binding, NOT an unsafe PDF
  // verdict. Never convert such errors into terminal document findings.
  if(await sha256(original)!==expectedHash)return empty(400);
  if(new TextDecoder().decode(original.slice(0,5))!=="%PDF-") {
    return signedUnsafeResponse(version,expectedHash,requestNonce,secrets.INSPECTOR_HMAC_KEY);
  }
  const headers=new Headers({
    "X-Folio-Inspector-Token":token,
    "X-Folio-Document-Version":version,
    "X-Folio-Source-Sha256":expectedHash,
    "Content-Type":"application/pdf",
    "Content-Length":String(original.length)
  });
  try{
    const inspection=await forward(new Request("http://container/inspect",{
      method:"POST",headers,body:original as BodyInit
    }));
    if(inspection.status===422){
      // Only this privileged gateway may attest an unsafe result. The parser
      // never receives the HMAC key, and its private error details are dropped.
      await inspection.body?.cancel();
      return signedUnsafeResponse(version,expectedHash,requestNonce,secrets.INSPECTOR_HMAC_KEY);
    }
    if(inspection.status!==200)return empty(503);
    if(!inspection.headers.get("Content-Type")?.toLowerCase().startsWith("application/json"))
      return empty(502);
    let report:Uint8Array;
    try{report=await readBounded(inspection.body,MAX_REPORT_BYTES);}
    catch{return empty(502);}
    if(!report.length)return empty(502);
    // The parser container is a lower-trust boundary: it gets NO HMAC signing
    // key. Canonicalization and signing happen only in this Worker.
    let manifest:InspectedTextManifest;
    let canonical:Uint8Array;
    try{
      const parsed:unknown=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(report));
      if(!parsed || typeof parsed!=="object" || Array.isArray(parsed)
        || Object.keys(parsed).length!==1 || !("manifest" in parsed))return empty(502);
      manifest=(parsed as {manifest:InspectedTextManifest}).manifest;
      canonical=serializeInspectionManifest(manifest);
    }catch{return empty(502);}
    if(manifest.documentVersionId!==version || manifest.sourceSha256!==expectedHash)return empty(502);
    const signature=await signCanonical(canonical,secrets.INSPECTOR_HMAC_KEY);
    const signed=new TextEncoder().encode(JSON.stringify({manifest,signature}));
    if(signed.byteLength>MAX_REPORT_BYTES)return empty(502);
    return new Response(new Uint8Array(signed).buffer,{status:200,headers:{
      ...RESPONSE_HEADERS,"Content-Type":"application/json; charset=utf-8"
    }});
  }catch{
    // Never reveal object keys, engine errors, private headers or tracebacks.
    return empty(503);
  }
}
