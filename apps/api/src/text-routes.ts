import {getDocumentTextPages} from "@folio/data";

export interface TextRouteEnv { DB: D1Database }
function json(value:unknown,status:number):Response {
  return Response.json(value,{status,headers:{
    "Cache-Control":"private, no-store, max-age=0",
    "X-Content-Type-Options":"nosniff",
    "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'"
  }});
}
/** Subject comes only from a verified Cloudflare Access JWT. */
export async function handleTextRequest(
  request:Request, env:TextRouteEnv, subject:string,commissionId:string,versionId:string
):Promise<Response> {
  if(request.method!=="GET")return json({error:"Method not allowed"},405);
  try {
    const pages=await getDocumentTextPages(env.DB,subject,commissionId,versionId);
    return pages?json(pages,200):json({error:"Not found"},404);
  }catch{
    return json({error:"Unable to retrieve inspected text"},503);
  }
}
