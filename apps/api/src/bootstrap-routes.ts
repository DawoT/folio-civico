import {
  createPilotCommission,validAccessSubject,
  CommissionBootstrapConflictError,CommissionBootstrapInputError
} from "@folio/data";

export interface BootstrapEnv {
  DB:D1Database;
  operatorSubject?:string;
}

type BootstrapAction="create"|"capability";

function json(data:unknown,status:number):Response {
  return Response.json(data,{status,headers:{
    "Cache-Control":"no-store","X-Content-Type-Options":"nosniff"
  }});
}

function trustedOperator(env:BootstrapEnv,subject:string):boolean {
  return Boolean(env.operatorSubject) && validAccessSubject(env.operatorSubject)
    && env.operatorSubject===subject;
}

async function readBootstrapBody(request:Request):
Promise<{name:string;initialPresidentSubject:string}> {
  if(request.headers.get("Content-Type")?.toLowerCase()!=="application/json") {
    throw new Error("Unsupported content type");
  }
  const length=request.headers.get("Content-Length");
  if(length && (!/^\d+$/.test(length)||Number(length)>4096)) {
    throw new RangeError("Request body too large");
  }
  if (!request.body) throw new Error("Missing request body");
  const stream=request.body.getReader();
  const chunks:Uint8Array[]=[];
  let size=0;
  try {
    while(true) {
      const {done,value}=await stream.read();
      if(done) break;
      size+=value.length;
      if(size>4096) {
        await stream.cancel("Exceeded maximum");
        throw new RangeError("Request body too large");
      }
      chunks.push(value);
    }
  } finally {stream.releaseLock();}
  const bytes=new Uint8Array(size);
  let offset=0;
  for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  const parsed:unknown=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
  if(!parsed || typeof parsed!=="object" || Array.isArray(parsed)) {
    throw new Error("Invalid bootstrap input");
  }
  const data=parsed as Record<string,unknown>;
  const names=Object.keys(data).sort();
  if(names.join(",")!=="initialPresidentSubject,name"
    || typeof data.name!=="string" || !validAccessSubject(data.initialPresidentSubject)) {
    throw new Error("Invalid bootstrap input");
  }
  return {name:data.name,initialPresidentSubject:data.initialPresidentSubject};
}

/** The root API must authenticate Access JWT before calling either action. */
export async function handleBootstrapRequest(
  request:Request,env:BootstrapEnv,subject:string,action:BootstrapAction
):Promise<Response> {
  if(action==="capability") {
    if(request.method!=="GET") return json({error:"Method not allowed"},405);
    return json({subject,canBootstrap:trustedOperator(env,subject)},200);
  }
  if(request.method!=="POST") return json({error:"Method not allowed"},405);
  // Fail closed when the operator binding is absent. No JWT is accepted
  // as global admin without a separate, explicitly configured trust root.
  if(!trustedOperator(env,subject)) return json({error:"Forbidden"},403);
  if(new URL(request.url).search) return json({error:"Unexpected query"},400);
  const origin=request.headers.get("Origin");
  if(origin && origin!==new URL(request.url).origin) return json({error:"Forbidden"},403);
  const requestKey=request.headers.get("Idempotency-Key");
  if(!requestKey||!/^[A-Za-z0-9_-]{8,96}$/.test(requestKey)) {
    return json({error:"Valid Idempotency-Key required"},400);
  }
  let input:{name:string;initialPresidentSubject:string};
  try {
    input=await readBootstrapBody(request);
  } catch(error) {
    if(error instanceof RangeError) return json({error:"Request body too large"},413);
    return json({error:"Malformed bootstrap input"},400);
  }
  try {
    const saved=await createPilotCommission(env.DB,{
      ...input,operatorSubject:subject,requestKey
    });
    return json(saved,saved.replayed?200:201);
  } catch(error) {
    if(error instanceof CommissionBootstrapConflictError) {
      return json({error:"Bootstrap conflict or limit reached"},409);
    }
    if(error instanceof CommissionBootstrapInputError) {
      return json({error:"Invalid bootstrap fields"},400);
    }
    return json({error:"Commission service unavailable"},503);
  }
}
