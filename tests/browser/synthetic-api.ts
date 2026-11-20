import { createHash } from "node:crypto";
import type { Page, Route } from "@playwright/test";

/**
 * Deterministic browser-only API double. This exercises React/DOM/keyboard
 * interactions, not Worker authorization: signed Worker E2E lives in Vitest.
 */
type Role = "president" | "member" | "advisor" | "observer";
interface Member { subject: string; role: Role; active: boolean; revision: number; }
interface Commission { id: string; name: string; status: "active" | "closed"; members: Map<string, Member>; }
interface Batch { id: string; commissionId: string; label: string; }
interface Checklist { id:string; commissionId:string; area:"works"|"procurement"; expectedDocument:string;status:"pending"; }
interface Evidence {
  type: "SEARCH_SCOPE";
  commissionId: string;
  checklistItemId: string;
  batchId: string;
  reviewerId: string;
  searchedAt: string;
}
interface Observation {
  id: string;
  commissionId: string;
  authorSubject: string;
  title: string;
  description: string;
  status: "draft" | "in_review" | "validated" | "dismissed";
  validatedBy: string | null;
  createdAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewNote: string | null;
  evidence: Evidence[];
}
interface Document {
  id: string; commissionId:string; batchId:string; filename:string;
  versionId:string; extractionStatus:"pending";sha256:string;
}
function json(response: unknown, status = 200) {
  return { status, contentType: "application/json; charset=utf-8",
    headers: { "Cache-Control": "no-store", "X-Content-Type-Options":"nosniff" },
    body: JSON.stringify(response) };
}

export class SyntheticPilotApi {
  readonly commission: Commission;
  readonly batches: Batch[] = [{id:"b_a",commissionId:"c_a",label:"Obras del piloto"}];
  readonly checklist:Checklist[] = [{id:"item_a",commissionId:"c_a",area:"works",expectedDocument:"Expediente de obra",status:"pending"}];
  readonly observations:Observation[] = [];
  readonly documents:Document[] = [];
  readonly calls: { actor:string; method:string; path:string; idempotencyKey:string|null }[]=[];
  readonly commissions: Commission[]=[];
  corruptExport = false;
  rehashedInvalidReview = false;
  private sequence=0;

  constructor() {
    this.commission={
      id:"c_a",name:"Comisión Piloto Sintética",status:"active",
      members:new Map([
        ["president",{subject:"president",role:"president",active:true,revision:1}],
        ["author",{subject:"author",role:"member",active:true,revision:1}],
        ["reviewer",{subject:"reviewer",role:"member",active:true,revision:1}],
        ["viewer",{subject:"viewer",role:"observer",active:true,revision:1}]
      ])
    };
    this.commissions.push(this.commission);
  }

  addHistory(count:number):void {
    for(let n=0;n<count;n++){
      const id="old_"+String(n).padStart(3,"0");
      this.observations.push({
        id,commissionId:"c_a",authorSubject:"author",
        title:"Histórico "+String(n).padStart(3,"0"),
        description:"Registro del periodo anterior",
        status:"validated",validatedBy:"reviewer",
        createdAt:"2026-11-18T10:00:00.000Z",
        reviewedBy:"reviewer",reviewedAt:"2026-11-18T11:00:00.000Z",
        reviewNote:"Comprobación de archivo anterior",
        evidence:[{
          type:"SEARCH_SCOPE",commissionId:"c_a",
          checklistItemId:"item_a",batchId:"b_a",reviewerId:"author",
          searchedAt:"2026-11-18T10:00:00.000Z"
        }]
      });
    }
  }

  async attach(page:Page, actor:string):Promise<void> {
    await page.route("**/api/**",route=>this.handle(route,actor));
  }

  private membership(commissionId:string,actor:string):Member|null {
    const member=this.commissions.find(c=>c.id===commissionId)?.members.get(actor);
    return member?.active?member:null;
  }
  private membershipRole(commissionId:string,actor:string):Role|null {
    return this.membership(commissionId,actor)?.role??null;
  }
  private allowed(commissionId:string,actor:string):boolean {
    return this.membership(commissionId,actor)!==null;
  }
  private itemFor(actor:string,record:Observation) {
    const role=this.membershipRole(record.commissionId,actor);
    return { ...record,
      canSubmit:record.status==="draft" && record.authorSubject===actor
        && (role==="president" || role==="member" || role==="advisor"),
      canReview:record.status==="in_review" && record.authorSubject!==actor
        && (role==="president" || role==="member")
    };
  }

  private async handle(route:Route, actor:string) {
    const req=route.request();
    const url=new URL(req.url());
    const {pathname:path}=url;
    const method=req.method();
    const key=req.headers()["idempotency-key"]??null;
    this.calls.push({actor,method,path:path+url.search,idempotencyKey:key});
    const respond=async(data:unknown,status=200)=>route.fulfill(json(data,status));
    const post=():Record<string,unknown>=>{
      try {return req.postDataJSON() as Record<string,unknown>;} catch {return {};}
    };
    if(path==="/api/session" && method==="GET") {
      return respond({subject:actor,canBootstrap:actor==="operator"});
    }
    if(path==="/api/commissions") {
      if(method==="GET") return respond(this.commissions.flatMap(c=>{
        const member=this.membership(c.id,actor);
        return member?[{id:c.id,name:c.name,status:c.status,role:member.role}]:[];
      }));
      if(method==="POST" && actor==="operator") {
        const body=post();
        const id="c_created_"+(++this.sequence);
        const president=String(body.initialPresidentSubject);
        const c:Commission={
          id,name:String(body.name),status:"active",
          members:new Map([[president,{subject:president,role:"president",active:true,revision:1}]])
        };
        this.commissions.push(c);
        return respond({id,name:c.name,initialPresidentSubject:president,replayed:false},201);
      }
      return respond({error:"Forbidden"},403);
    }
    const routeParts=path.split("/").filter(Boolean);
    if(routeParts[0]!=="api" || routeParts[1]!=="commissions" || !routeParts[2]) {
      return respond({error:"Not found"},404);
    }
    const cid=routeParts[2];
    if(!this.allowed(cid,actor)) return respond({error:"Not found"},404);
    const role=this.membershipRole(cid,actor);
    if(routeParts[3]==="batches" && routeParts.length===4){
      if(method==="GET")return respond(this.batches.filter(b=>b.commissionId===cid));
      if(method==="POST" && role==="president"){
        const body=post();
        const entry={id:"b_created_"+(++this.sequence),commissionId:cid,label:String(body.label)};
        this.batches.push(entry);
        return respond({id:entry.id,label:entry.label,replayed:false},201);
      }
    }
    if(routeParts[3]==="members"){
      if(role!=="president")return respond({error:"Forbidden"},403);
      const commission=this.commissions.find(c=>c.id===cid)!;
      if(routeParts.length===4 && method==="GET"){
        return respond([...commission.members.values()]);
      }
      if(method==="POST"){
        const body=post();
        const subject=String(body.subject);
        const current=commission.members.get(subject);
        if(routeParts.length===5 && routeParts[4]==="revoke"){
          if(!current || subject===actor)return respond({error:"Forbidden"},403);
          current.active=false;current.revision++;
          return respond({...current,replayed:false});
        }
        if(routeParts.length===4){
          if(current){
            current.role=String(body.role) as Role;
            current.active=true;current.revision++;
            return respond({...current,replayed:false});
          }
          const m:Member={subject,role:String(body.role) as Role,active:true,revision:1};
          commission.members.set(subject,m);
          return respond({...m,replayed:false},201);
        }
      }
    }
    if(routeParts[3]==="checklist"){
      if(routeParts.length===4 && method==="GET"){
        return respond(this.checklist.filter(i=>i.commissionId===cid).map(i=>{
          const validated=this.observations.find(o=>o.commissionId===cid &&
            o.status==="validated" && o.evidence.some(e=>e.checklistItemId===i.id));
          return {id:i.id,area:i.area,expectedDocument:i.expectedDocument,
            status:validated?"not_located":"pending",
            statusSource:validated?"validated_search":"stored",
            validatedSearchObservationId:validated?.id??null,
            reviewedBy:validated?.reviewedBy??null,
            reviewedAt:validated?.reviewedAt??null};
        }));
      }
      if(routeParts.length===5 && routeParts[4]==="items" && method==="POST" && role==="president"){
        const data=post();
        const item:Checklist={
          id:"item_created_"+(++this.sequence),commissionId:cid,
          area:String(data.area) as "works"|"procurement",
          expectedDocument:String(data.expectedDocument),status:"pending"
        };
        this.checklist.push(item);
        return respond({...item,replayed:false},201);
      }
    }
    if(routeParts[3]==="batches" && routeParts[5]==="documents"){
      const bid=routeParts[4];
      if(!bid)return respond({error:"Not found"},404);
      if(method==="GET")return respond(this.documents.filter(d=>d.commissionId===cid && d.batchId===bid));
      if(method==="POST"){
        const filename=decodeURIComponent(req.headers()["x-document-filename"]??"synthetic.pdf");
        const bytes=req.postDataBuffer()??Buffer.alloc(0);
        const id="document_"+(++this.sequence);
        const versionId="version_"+this.sequence;
        const sha=createHash("sha256").update(bytes).digest("hex");
        this.documents.push({id,commissionId:cid,batchId:bid,filename,versionId,extractionStatus:"pending",sha256:sha});
        return respond({documentId:id,versionId,sha256:sha,repeated:false,ingestStatus:"quarantined",processingStatus:"pending"},201);
      }
    }
    if(routeParts[3]==="observations"){
      const action=routeParts[4]??"";
      if(action==="history" && method==="GET"){
        const limit=Number(url.searchParams.get("limit")??25);
        const cursor=url.searchParams.get("cursor");
        const offset=cursor?Number(cursor.split("_").at(-1)):0;
        const visible=this.observations.filter(o=>o.commissionId===cid).slice().reverse();
        const records=visible.slice(offset,offset+limit).map(o=>this.itemFor(actor,o));
        const next=offset+limit<visible.length?"browser_cursor_"+(offset+limit):null;
        return respond({items:records,nextCursor:next});
      }
      if(action==="drafts" && method==="POST"){
        const data=post();
        const record:Observation={
          id:"obs_"+(++this.sequence),commissionId:cid,authorSubject:actor,
          title:String(data.title),description:String(data.description),
          status:"draft",validatedBy:null,reviewedBy:null,reviewedAt:null,reviewNote:null,
          createdAt:new Date().toISOString(),
          evidence:[{
            type:"SEARCH_SCOPE",commissionId:cid,
            checklistItemId:String(data.checklistItemId),batchId:String(data.batchId),
            reviewerId:actor,searchedAt:new Date().toISOString()
          }]
        };
        this.observations.push(record);
        return respond(this.itemFor(actor,record),201);
      }
      if(action==="export" && method==="GET"){
        const records=this.observations.filter(o=>o.commissionId===cid &&
          (o.status==="validated" || o.status==="dismissed")).map(record=>
            this.rehashedInvalidReview ? {...record,reviewedBy:record.authorSubject} : record
          );
        const commission=this.commissions.find(item=>item.id===cid);
        const payload=JSON.stringify({
          schemaVersion:1,kind:"internal_human_review",
          generatedAt:new Date().toISOString(),
          commission:{id:cid,name:commission?.name,status:commission?.status},
          completeness:{
            statuses:["validated","dismissed"],included:records.length,
            truncated:false,maximumPerExport:500
          },
          observations:records,disclaimer:"No constituye acta oficial."
        });
        const sha=createHash("sha256").update(payload).digest("hex");
        const header=payload;
        return route.fulfill({
          ...json({format:"folio-civico.review-export.v1",
            payload:this.corruptExport?header+"tampered":payload,sha256:sha}),
          headers:{"Cache-Control":"no-store","X-Report-SHA256":sha}
        });
      }
      if(action && routeParts.length===5 && method==="GET"){
        const record=this.observations.find(o=>o.id===action && o.commissionId===cid);
        return record?respond(record):respond({error:"Not found"},404);
      }
      if(action && routeParts[5]==="actions" && method==="POST"){
        const data=post();
        const record=this.observations.find(o=>o.id===action && o.commissionId===cid);
        if(!record)return respond({error:"Not found"},404);
        if(data.action==="submit" && record.authorSubject===actor && record.status==="draft"){
          record.status="in_review";
          return respond({...this.itemFor(actor,record),replayed:false});
        }
        if(["validate","dismiss"].includes(String(data.action)) &&
          record.authorSubject!==actor && record.status==="in_review" &&
          (role==="member"||role==="president")){
          record.status=data.action==="validate"?"validated":"dismissed";
          record.validatedBy=record.status==="validated"?actor:null;
          record.reviewedBy=actor;record.reviewedAt=new Date().toISOString();
          record.reviewNote=String(data.note);
          return respond({...this.itemFor(actor,record),replayed:false});
        }
        return respond({error:"Forbidden"},403);
      }
    }
    return respond({error:"Not found"},404);
  }
}
