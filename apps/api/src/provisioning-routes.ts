import {
  createCommissionBatch, createCommissionChecklistItem,
  getCommissionSummary, ProvisioningAccessError, ProvisioningConflictError,
  ProvisioningInputError
} from "@folio/data";

export type ProvisioningKind = "batch" | "checklist";
export interface ProvisioningEnv { DB: D1Database; }
const MAX_BODY=4096;

function json(body:unknown,status:number):Response {
  return Response.json(body,{status,headers:{
    "Cache-Control":"no-store","X-Content-Type-Options":"nosniff"
  }});
}
class BodyError extends Error {
  constructor(readonly status:number,message:string){super(message);}
}

async function readBody(request:Request,kind:ProvisioningKind):
Promise<{label:string}|{area:"works"|"procurement";expectedDocument:string}> {
  if(request.headers.get("Content-Type")?.toLowerCase()!=="application/json") {
    throw new BodyError(415,"Only JSON is supported");
  }
  const declared=request.headers.get("Content-Length");
  if(declared && (!/^\d+$/.test(declared)||Number(declared)>MAX_BODY)) {
    throw new BodyError(413,"Provisioning body too large");
  }
  if(!request.body) throw new BodyError(400,"Missing request body");
  const reader=request.body.getReader();
  let size=0;const chunks:Uint8Array[]=[];
  try {
    while(true) {
      const part=await reader.read();
      if(part.done) break;
      size+=part.value.byteLength;
      if(size>MAX_BODY) {
        await reader.cancel("Body limit");
        throw new BodyError(413,"Provisioning body too large");
      }
      chunks.push(part.value);
    }
  } finally {reader.releaseLock();}
  const bytes=new Uint8Array(size);let position=0;
  for(const part of chunks){bytes.set(part,position);position+=part.length;}
  let parsed:unknown;
  try{parsed=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
  catch{throw new BodyError(400,"Invalid JSON");}
  if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)) {
    throw new BodyError(400,"Invalid provisioning payload");
  }
  const body=parsed as Record<string,unknown>;
  if(kind==="batch") {
    if(Object.keys(body).length!==1||typeof body.label!=="string") {
      throw new BodyError(400,"Only a batch label is accepted");
    }
    return {label:body.label};
  }
  if(Object.keys(body).length!==2||typeof body.expectedDocument!=="string"
    ||(body.area!=="works"&&body.area!=="procurement")) {
    throw new BodyError(400,"Checklist area and expected document required");
  }
  return {area:body.area,expectedDocument:body.expectedDocument};
}

/** Called exclusively after successful Access JWT verification by the API Worker. */
export async function handleProvisioningRequest(
  request:Request,env:ProvisioningEnv,subject:string,commissionId:string,kind:ProvisioningKind
):Promise<Response> {
  if(request.method!=="POST") return json({error:"Method not allowed"},405);
  if(new URL(request.url).search) return json({error:"Unknown provisioning filters"},400);
  const origin=request.headers.get("Origin");
  if(origin&&origin!==new URL(request.url).origin) return json({error:"Forbidden"},403);
  try {
    const commission=await getCommissionSummary(env.DB,subject,commissionId);
    if(!commission) return json({error:"Not found"},404);
    if(commission.role!=="president") return json({error:"Forbidden"},403);
    if(commission.status!=="active") return json({error:"Commission closed"},409);
    const requestKey=request.headers.get("Idempotency-Key");
    if(!requestKey||!/^[A-Za-z0-9_-]{8,96}$/.test(requestKey)) {
      return json({error:"Valid Idempotency-Key required"},400);
    }
    const body=await readBody(request,kind);
    const input={commissionId,subject,requestKey};
    const saved=kind==="batch"
      ? await createCommissionBatch(env.DB,{...input,label:(body as {label:string}).label})
      : await createCommissionChecklistItem(env.DB,{
        ...input,...body as {area:"works"|"procurement";expectedDocument:string}
      });
    return json(saved,saved.replayed?200:201);
  } catch(error) {
    if(error instanceof BodyError) return json({error:error.message},error.status);
    if(error instanceof ProvisioningInputError) return json({error:"Invalid provisioning fields"},400);
    if(error instanceof ProvisioningAccessError) return json({error:"Forbidden"},403);
    if(error instanceof ProvisioningConflictError) return json({error:"Provisioning conflict or limit reached"},409);
    return json({error:"Provisioning unavailable"},503);
  }
}
