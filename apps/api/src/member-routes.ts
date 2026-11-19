import {
  getCommissionSummary, listCommissionMembers, grantCommissionMember,
  revokeCommissionMember, validAccessSubject,
  MembershipAccessError, MembershipConflictError, MembershipInputError,
  type GrantMemberInput, type MembershipChangeInput
} from "@folio/data";

export interface MemberEnv {DB:D1Database}
type MemberAction="members"|"revoke";
class RequestError extends Error {
  constructor(readonly status:number,message:string){super(message);}
}
function json(data:unknown,status:number):Response {
  return Response.json(data,{status,headers:{
    "Cache-Control":"no-store","X-Content-Type-Options":"nosniff"
  }});
}

/** Strict JSON parser with a bounded streaming read, not an unbounded text(). */
async function readMemberBody(request:Request,action:MemberAction):
Promise<{subject:string;expectedRevision:number|null;role?:GrantMemberInput["role"]}> {
  if (request.headers.get("Content-Type")?.toLowerCase()!=="application/json") {
    throw new RequestError(415,"Expected application/json");
  }
  const length=request.headers.get("Content-Length");
  if (length && (!/^\d+$/.test(length) || Number(length)>4096)) {
    throw new RequestError(413,"Request body too large");
  }
  if (!request.body) throw new RequestError(400,"Missing body");
  const stream=request.body.getReader();
  let size=0;
  const chunks:Uint8Array[]=[];
  try {
    while (true) {
      const {done,value}=await stream.read();
      if(done) break;
      size+=value.length;
      if(size>4096) {
        await stream.cancel("Exceeded maximum");
        throw new RequestError(413,"Request body too large");
      }
      chunks.push(value);
    }
  } finally {stream.releaseLock();}
  const bytes=new Uint8Array(size);
  let index=0;
  for(const chunk of chunks){bytes.set(chunk,index);index+=chunk.length;}
  let parsed:unknown;
  try{parsed=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
  catch{throw new RequestError(400,"Malformed JSON");}
  if(!parsed || typeof parsed!=="object" || Array.isArray(parsed)) {
    throw new RequestError(400,"Invalid member payload");
  }
  const body=parsed as Record<string,unknown>;
  const keys=Object.keys(body).sort();
  const expected=action==="members"
    ? ["expectedRevision","role","subject"]
    : ["expectedRevision","subject"];
  if(keys.join(",")!==expected.join(",")
    || !validAccessSubject(body.subject)
    || (body.expectedRevision!==null && (!Number.isSafeInteger(body.expectedRevision)
      || (body.expectedRevision as number)<1 || (body.expectedRevision as number)>2147483646))
    || (action==="revoke" && body.expectedRevision===null)
    || (action==="members" && !["president","member","advisor","observer"].includes(body.role as string))) {
    throw new RequestError(400,"Invalid member fields or revision");
  }
  return {
    subject:body.subject,
    expectedRevision:body.expectedRevision as number|null,
    ...(action==="members"?{role:body.role as GrantMemberInput["role"]}:{})
  };
}

/** Called only after validating the Access JWT in the API root. */
export async function handleMemberRequest(
  request:Request,env:MemberEnv,actor:string,commissionId:string,action:MemberAction
):Promise<Response> {
  const method=request.method;
  if (action==="revoke" ? method!=="POST" : !["GET","POST"].includes(method)) {
    return json({error:"Method not allowed"},405);
  }
  if(new URL(request.url).search) return json({error:"Unknown query parameters"},400);
  const origin=request.headers.get("Origin");
  if(origin && origin!==new URL(request.url).origin) return json({error:"Forbidden"},403);
  try {
    const commission=await getCommissionSummary(env.DB,actor,commissionId);
    if(!commission) return json({error:"Not found"},404);
    if(commission.role!=="president") return json({error:"Forbidden"},403);

    if(method==="GET") {
      const members=await listCommissionMembers(env.DB,actor,commissionId);
      return json(members,200);
    }
    if(commission.status!=="active") return json({error:"Commission closed"},409);
    const requestKey=request.headers.get("Idempotency-Key");
    if(!requestKey||!/^[A-Za-z0-9_-]{8,96}$/.test(requestKey)) {
      return json({error:"Valid Idempotency-Key required"},400);
    }
    const body=await readMemberBody(request,action);
    const input:MembershipChangeInput={
      commissionId,actorSubject:actor,memberSubject:body.subject,
      expectedRevision:body.expectedRevision,requestKey
    };
    const outcome=action==="members"
      ? await grantCommissionMember(env.DB,{...input,role:body.role!})
      : await revokeCommissionMember(env.DB,input);
    return json(outcome,action==="members" && input.expectedRevision===null && !outcome.replayed ?201:200);
  } catch (problem) {
    if(problem instanceof RequestError) return json({error:problem.message},problem.status);
    if(problem instanceof MembershipInputError) return json({error:"Invalid membership fields"},400);
    if(problem instanceof MembershipAccessError) return json({error:"Forbidden"},403);
    if(problem instanceof MembershipConflictError) return json({error:"Membership changed or request conflict"},409);
    return json({error:"Membership service unavailable"},503);
  }
}
