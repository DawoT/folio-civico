import {countReviewableObservations, getCommissionSummary} from "@folio/data";

export interface ReviewableCountEnv { DB:D1Database; }

function json(body:unknown,status:number):Response {
  return Response.json(body,{
    status,headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}
  });
}

function eligible(summary:{status:"active"|"closed";role:string}):boolean {
  return summary.status==="active"
    && (summary.role==="president" || summary.role==="member");
}

/**
 * Returns a commission-wide count, never a count from a partly loaded page.
 * The verified JWT subject is provided by the API Worker. A final membership
 * read prevents an expired role or a revocation during COUNT from disclosing
 * stale capabilities; this is not a cross-request snapshot transaction.
 */
export async function handleReviewableCountRequest(
  request:Request,env:ReviewableCountEnv,subject:string,commissionId:string
):Promise<Response> {
  if(request.method!=="GET") return json({error:"Method not allowed"},405);
  if(new URL(request.url).search) return json({error:"Filters are not supported"},400);
  try {
    const initial=await getCommissionSummary(env.DB,subject,commissionId);
    if(!initial) return json({error:"Not found"},404);
    const initiallyEligible=eligible(initial);
    const count=initiallyEligible
      ? await countReviewableObservations(env.DB,subject,commissionId)
      : 0;
    // Even an empty queue must not acknowledge a commission after membership
    // revocation. Never grant capabilities on a concurrent promotion.
    const current=await getCommissionSummary(env.DB,subject,commissionId);
    if(!current) return json({error:"Not found"},404);
    return json({commissionId,count:initiallyEligible && eligible(current)?count:0},200);
  }catch {
    return json({error:"Request could not be completed"},503);
  }
}
