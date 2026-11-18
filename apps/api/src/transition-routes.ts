import {
  getCommissionSummary, transitionObservation, ReviewAccessError, ReviewConflictError,
  type ObservationAction
} from "@folio/data";

export interface TransitionEnv { DB: D1Database }
function json(body:unknown,status:number):Response {
  return Response.json(body,{status,headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
}
const MAX_ACTION_BODY=2048;

async function parseAction(request:Request):Promise<{action:ObservationAction;note?:string}> {
  if (request.headers.get("Content-Type")?.toLowerCase()!=="application/json") {
    throw new TransitionBodyError(415,"Only JSON is supported");
  }
  const length=request.headers.get("Content-Length");
  if (length!==null && (!/^\d+$/.test(length) || Number(length)>MAX_ACTION_BODY)) {
    throw new TransitionBodyError(413,"Action exceeds maximum body size");
  }
  if (!request.body) throw new TransitionBodyError(400,"Missing action body");
  const reader=request.body.getReader();
  let size=0;
  const chunks:Uint8Array[]=[];
  try {
    while(true) {
      const chunk=await reader.read();
      if(chunk.done) break;
      size+=chunk.value.byteLength;
      if(size>MAX_ACTION_BODY) {
        await reader.cancel("Body limit");
        throw new TransitionBodyError(413,"Action exceeds maximum body size");
      }
      chunks.push(chunk.value);
    }
  } finally { reader.releaseLock(); }
  const bytes=new Uint8Array(size);
  let offset=0;
  for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
  let parsed:unknown;
  try {parsed=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
  catch {throw new TransitionBodyError(400,"Invalid JSON");}
  if(!parsed || typeof parsed!=="object" || Array.isArray(parsed)) {
    throw new TransitionBodyError(400,"Invalid action payload");
  }
  const fields=parsed as Record<string,unknown>;
  const allowed = ["action","note"];
  if(Object.keys(fields).some(key=>!allowed.includes(key))) {
    throw new TransitionBodyError(400,"Unknown action fields");
  }
  const action=fields.action;
  if(action!=="submit" && action!=="validate" && action!=="dismiss") {
    throw new TransitionBodyError(400,"Invalid review action");
  }
  if(action==="submit") {
    if(Object.keys(fields).length!==1) throw new TransitionBodyError(400,"Submit does not accept a decision rationale");
    return {action};
  }
  const note=fields.note;
  if(Object.keys(fields).length!==2 || typeof note!=="string"
    || note.trim().length<15 || note.length>1000) {
    throw new TransitionBodyError(400,"Human decision requires a rationale of 15–1000 characters");
  }
  return {action,note:note.trim()};
}
class TransitionBodyError extends Error {
  constructor(readonly status:number,message:string){super(message);}
}

/** Authorized, same-origin state transition; subjects never come from request bodies. */
export async function handleTransitionRequest(
  request:Request,env:TransitionEnv,subject:string,commissionId:string,observationId:string
):Promise<Response> {
  if(request.method!=="POST") return json({error:"Method not allowed"},405);
  try {
    const commission=await getCommissionSummary(env.DB,subject,commissionId);
    if(!commission) return json({error:"Not found"},404);
    if(commission.status!=="active") return json({error:"Commission closed"},409);
    const origin=request.headers.get("Origin");
    if(origin && origin!==new URL(request.url).origin) return json({error:"Forbidden"},403);
    const requestKey=request.headers.get("Idempotency-Key");
    if(!requestKey || !/^[A-Za-z0-9_-]{8,96}$/.test(requestKey)) {
      return json({error:"Valid Idempotency-Key required"},400);
    }
    const action=await parseAction(request);
    const result=await transitionObservation(env.DB,{
      commissionId,subject,observationId,action:action.action,note:action.note,requestKey
    });
    const {submitRequestKey:unusedSubmit,reviewRequestKey:unusedReview,...publicObservation}=result.observation;
    void unusedSubmit;void unusedReview;
    return json({...publicObservation,replayed:result.replayed},200);
  } catch(error) {
    if(error instanceof TransitionBodyError) return json({error:error.message},error.status);
    if(error instanceof ReviewAccessError) return json({error:error.message==="Observation not found"?"Not found":"Forbidden"},
      error.message==="Observation not found"?404:403);
    if(error instanceof ReviewConflictError) return json({error:"Transition conflict or evidence no longer valid"},409);
    return json({error:"Request could not be completed"},503);
  }
}
