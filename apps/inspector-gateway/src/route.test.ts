import { describe, expect, it, vi } from "vitest";
import { serializeInspectionManifest,serializeUnsafeInspectionVerdict,type UnsafeInspectionVerdict,type InspectedTextManifest } from "@folio/data";
import { handleInspectorGatewayRequest } from "./route";

const sampleServiceCredential = "test-service-".repeat(4);
const signingKey = "synthetic-hmac-key-".repeat(3);
const requestNonce="0123456789abcdef0123456789abcdef";
const bytes = new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
const sha = async (content: Uint8Array): Promise<string> =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(content).buffer)))
    .map(n => n.toString(16).padStart(2,"0")).join("");

const env = { INSPECTOR_SERVICE_TOKEN:sampleServiceCredential, INSPECTOR_HMAC_KEY:signingKey };
async function request(overrides: Record<string,string> = {}, body: Uint8Array = bytes) {
  return new Request("https://inspector.internal/inspect",{
    method:"POST",
    headers:{
      "X-Folio-Inspector-Token":sampleServiceCredential,
      "Content-Type":"application/pdf",
      "X-Folio-Document-Version":"version_01",
      "X-Folio-Source-Sha256":await sha(body),
      "X-Folio-Inspection-Nonce":requestNonce,
      ...overrides
    },
    body:body as BodyInit
  });
}
async function manifestFor(content:Uint8Array=bytes):Promise<InspectedTextManifest>{
  return {
    documentVersionId:"version_01",sourceSha256:await sha(content),
    scanVerdict:"clean",scanner:"isolated-scanner-v1",scannerReportId:"scan_test_12345",
    scannedAt:"2026-11-18T19:00:00.000Z",
    pages:[{page:1,text:"Páginas de expediente verificado"}]
  };
}

describe("internal Cloudflare Container inspector gateway",()=>{
  it("blocks all requests without a valid private service sampleServiceCredential before forwarding",async()=>{
    const forward=vi.fn(async()=>new Response(null,{status:200}));
    for(const forged of ["wrong",""]){
      const result=await handleInspectorGatewayRequest(await request({
        "X-Folio-Inspector-Token":forged
      }),env,forward);
      expect(result.status).toBe(403);
      expect(result.headers.get("Cache-Control")).toContain("no-store");
    }
    expect(forward).not.toHaveBeenCalled();
  });

  it("denies method, path, query, Origin, mismatched SHA and unsupported media type",async()=>{
    const forward=vi.fn(async()=>Response.json({status:"ok"}));
    const bad=[
      new Request("https://inspector.internal/"),
      new Request("https://inspector.internal/inspect?inspect=true",{method:"POST"}),
      await request({Origin:"https://evil.test"}),
      await request({"X-Folio-Source-Sha256":"a".repeat(64)}),
      await request({"Content-Type":"text/plain"}),
      await request({"X-Folio-Inspection-Nonce":""})
    ];
    for(const value of bad){
      const response=await handleInspectorGatewayRequest(value,env,forward);
      expect(response.status).not.toBe(200);
    }
    expect(forward).not.toHaveBeenCalled();
  });

  it("signs a matching clean manifest ONLY in the gateway, after inspecting the original",async()=>{
    let seen:Request|undefined;
    const unsigned=await manifestFor();
    const forward=vi.fn(async(incoming:Request)=>{
      seen=incoming;
      return Response.json({manifest:unsigned},{
        headers:{"Set-Cookie":"sensitive=1","X-R2-Key":"quarantine/private.pdf"}
      });
    });
    const original=await request({"X-Evil-Header":"unsafe"});
    const response=await handleInspectorGatewayRequest(original,env,forward);
    expect(response.status).toBe(200);
    expect(seen).toBeDefined();
    expect(new URL(seen!.url).pathname).toBe("/inspect");
    expect(seen!.headers.get("X-Evil-Header")).toBeNull();
    expect(seen!.headers.get("X-Folio-Inspector-Token")).toBe(sampleServiceCredential);
    expect(seen!.headers.get("X-Folio-Inspection-Nonce")).toBeNull();
    expect(seen!.headers.has("INSPECTOR_HMAC_KEY")).toBe(false);
    expect(new Uint8Array(await seen!.arrayBuffer())).toEqual(bytes);
    expect(response.headers.get("Set-Cookie")).toBeNull();
    expect(response.headers.get("X-R2-Key")).toBeNull();
    expect(response.headers.get("Content-Type")).toContain("application/json");
    const signed=await response.json() as {manifest:InspectedTextManifest;signature:string};
    expect(signed.manifest).toEqual(unsigned);
    const cryptoKey=await crypto.subtle.importKey("raw",new TextEncoder().encode(signingKey),
      {name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const signature=new Uint8Array(signed.signature.match(/../g)!.map(hex=>parseInt(hex,16)));
    expect(await crypto.subtle.verify("HMAC",cryptoKey,signature,
      new Uint8Array(serializeInspectionManifest(signed.manifest)).buffer)).toBe(true);
    expect(JSON.stringify(signed)).not.toContain(signingKey);
  });

  it("refuses forged, non-clean, different-version and different-hash scanner output",async()=>{
    const valid=await manifestFor();
    for(const result of [
      {...valid,scanVerdict:"infected"},
      {...valid,documentVersionId:"other_version"},
      {...valid,sourceSha256:"b".repeat(64)},
      {...valid,pages:[{page:3,text:"Unknown page"}]}
    ]){
      const response=await handleInspectorGatewayRequest(await request(),env,
        async()=>Response.json({manifest:result}));
      expect(response.status).toBe(502);
    }
    const alreadySigned=await handleInspectorGatewayRequest(await request(),env,
      async()=>Response.json({manifest:valid,signature:"b".repeat(64)}));
    expect(alreadySigned.status).toBe(502);
  });

  it("signs a matching malformed PDF finding but never treats SHA mismatch as unsafe",async()=>{
    const forward=vi.fn(async()=>new Response(null,{status:422}));
    const malformed=new TextEncoder().encode("not-a-pdf-file-but-with-a-valid-hash");
    const signed=await handleInspectorGatewayRequest(
      await request({},malformed),env,forward
    );
    expect(signed.status).toBe(422);
    const data=await signed.json() as {verdict:UnsafeInspectionVerdict;signature:string};
    expect(data.verdict).toMatchObject({
      kind:"folio.inspection.unsafe.v1",sourceSha256:await sha(malformed),
      requestNonce,documentVersionId:"version_01"
    });
    expect(data.signature).toMatch(/^[a-f0-9]{64}$/);
    expect(forward).not.toHaveBeenCalled();

    const mismatch=await handleInspectorGatewayRequest(await request({
      "X-Folio-Source-Sha256":"f".repeat(64)
    }),env,forward);
    expect(mismatch.status).toBe(400);
    expect(await mismatch.text()).toBe("");
    expect(forward).not.toHaveBeenCalled();
  });

  it("provides a signed terminal 422 for a previously quarantined short PDF",async()=>{
    const forward=vi.fn(async()=>Response.json({unexpected:true}));
    const short=new TextEncoder().encode("%PDF-1.7");
    const result=await handleInspectorGatewayRequest(
      await request({},short),env,forward
    );
    expect(result.status).toBe(422);
    expect(result.headers.get("Content-Type")).toContain("application/json");
    const signed=await result.json() as {verdict:UnsafeInspectionVerdict;signature:string};
    expect(signed.verdict).toEqual({
      kind:"folio.inspection.unsafe.v1",
      documentVersionId:"version_01",
      sourceSha256:await sha(short),
      requestNonce
    });
    const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(signingKey),
      {name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const signature=new Uint8Array(signed.signature.match(/../g)!.map(x=>parseInt(x,16)));
    expect(await crypto.subtle.verify(
      "HMAC",key,signature,
      new Uint8Array(serializeUnsafeInspectionVerdict(signed.verdict)).buffer
    )).toBe(true);
    expect(forward).not.toHaveBeenCalled();

    const tampered=await handleInspectorGatewayRequest(
      await request({"X-Folio-Source-Sha256":"f".repeat(64)},short),env,forward
    );
    expect(tampered.status).toBe(400);
    expect(await tampered.text()).toBe("");
    expect(forward).not.toHaveBeenCalled();
  });

  it("caps payloads before forwarding and caps inspection responses after forwarding",async()=>{
    const forward=vi.fn(async()=>new Response("X".repeat(2*1024*1024+1),{
      status:200,headers:{"Content-Type":"application/json"}
    }));
    const oversized=await request({},new Uint8Array(8*1024*1024+1).fill(1));
    const rejected=await handleInspectorGatewayRequest(oversized,env,forward);
    expect(rejected.status).toBe(413);
    expect(forward).not.toHaveBeenCalled();

    const invalidResponse=await handleInspectorGatewayRequest(await request(),env,forward);
    expect(invalidResponse.status).toBe(502);
  });

  it("keeps 422 as needs_review, converts failures to retryable 503 and never echoes private details",async()=>{
    const reject=vi.fn(async()=>new Response("internal-debug-secret",{status:422}));
    const r=await handleInspectorGatewayRequest(await request(),env,reject);
    expect(r.status).toBe(422);
    expect(r.headers.get("Cache-Control")).toContain("no-store");
    const signed=await r.json() as {verdict:UnsafeInspectionVerdict;signature:string};
    expect(signed.verdict).toEqual({
      kind:"folio.inspection.unsafe.v1",
      documentVersionId:"version_01",sourceSha256:await sha(bytes),
      requestNonce
    });
    const cryptoKey=await crypto.subtle.importKey("raw",new TextEncoder().encode(signingKey),
      {name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const sig=new Uint8Array(signed.signature.match(/../g)!.map(hex=>parseInt(hex,16)));
    expect(await crypto.subtle.verify(
      "HMAC",cryptoKey,sig,
      new Uint8Array(serializeUnsafeInspectionVerdict(signed.verdict)).buffer
    )).toBe(true);
    expect(JSON.stringify(signed)).not.toContain("internal-debug-secret");

    const unavailable=vi.fn(async()=>{throw new Error("quarantine/secret.pdf");});
    const result=await handleInspectorGatewayRequest(await request(),env,unavailable);
    expect(result.status).toBe(503);
    expect(await result.text()).not.toContain("quarantine/");
  });

  it("fails closed when gateway signing credentials are missing",async()=>{
    const forward=vi.fn(async()=>Response.json({}));
    const response=await handleInspectorGatewayRequest(await request(),
      {INSPECTOR_SERVICE_TOKEN:sampleServiceCredential,INSPECTOR_HMAC_KEY:undefined},forward);
    expect(response.status).toBe(503);
    expect(forward).not.toHaveBeenCalled();
  });
});
