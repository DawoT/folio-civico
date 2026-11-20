import {
  serializeUnsafeInspectionVerdict,type UnsafeInspectionVerdict
} from "../../packages/data/src/inspected-text";

/** Test-only stand-in for the privileged gateway. NEVER used in production. */
export async function syntheticSignedUnsafeResponse(
  request:Request,secret:string,override:Partial<UnsafeInspectionVerdict>={}
):Promise<Response>{
  const verdict:UnsafeInspectionVerdict={
    kind:"folio.inspection.unsafe.v1",
    documentVersionId:request.headers.get("X-Folio-Document-Version")??"",
    sourceSha256:request.headers.get("X-Folio-Source-Sha256")??"",
    requestNonce:request.headers.get("X-Folio-Inspection-Nonce")??"",
    ...override
  };
  const key=await crypto.subtle.importKey(
    "raw",new TextEncoder().encode(secret),
    {name:"HMAC",hash:"SHA-256"},false,["sign"]
  );
  const signature=Array.from(new Uint8Array(await crypto.subtle.sign(
    "HMAC",key,new Uint8Array(serializeUnsafeInspectionVerdict(verdict)).buffer
  )),n=>n.toString(16).padStart(2,"0")).join("");
  return Response.json({verdict,signature},{status:422});
}
