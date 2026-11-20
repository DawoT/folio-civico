import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {handleMemberRequest} from "./member-routes";

function fixture(){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('a','Comisión A','active'),('closed','Cerrada','closed');
    INSERT INTO commission_members(commission_id,subject,role,active)
    VALUES ('a','president','president',1),('a','member','member',1),
      ('a','reader','observer',1),('a','inactive','advisor',0),
      ('closed','president','president',1);
  `);
  return f;
}
const base="https://folio.test/api/commissions/a/members";
function post(path:string,body:unknown,key:string,origin?:string){
  return new Request("https://folio.test"+path,{
    method:"POST",headers:{"Content-Type":"application/json","Idempotency-Key":key,
      ...(origin?{Origin:origin}:{})},
    body:JSON.stringify(body)
  });
}

function afterAuthorizedRows(db:D1Database,needle:string,change:()=>void):D1Database {
  let triggered=false;
  return {
    prepare(sql:string) {
      const statement=db.prepare(sql);
      if(!sql.includes(needle)) return statement;
      return {
        bind(...values:unknown[]) {
          const bound=statement.bind(...values);
          return {
            async all<T>() {
              const result=await bound.all<T>();
              if(!triggered) {triggered=true;change();}
              return result;
            }
          };
        }
      } as unknown as D1PreparedStatement;
    }
  } as D1Database;
}

describe("authenticated membership management endpoint",()=>{
  it.each(["revoked","demoted"] as const)(
    "does not reveal the membership roster after the president is %s during D1 list",
    async(change)=>{
      const f=fixture();
      try {
        const raced=afterAuthorizedRows(f.db,"SELECT m.subject,m.role,m.active,m.revision",()=>{
          f.sqlite.exec(change==="revoked"
            ? "UPDATE commission_members SET active=0 WHERE commission_id='a' AND subject='president'"
            : "UPDATE commission_members SET role='member' WHERE commission_id='a' AND subject='president'");
        });
        const res=await handleMemberRequest(new Request(base),{DB:raced},"president","a","members");
        expect(res.status).toBe(change==="revoked"?404:403);
        expect(await res.json()).toEqual({error:change==="revoked"?"Not found":"Forbidden"});
        expect(res.headers.get("Cache-Control")).toBe("no-store");
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:0});
      }finally{f.close();}
    }
  );


  it("GET returns the complete scoped member list only to active presidents",async()=>{
    const f=fixture();
    try {
      const allowed=await handleMemberRequest(new Request(base),{DB:f.db},"president","a","members");
      expect(allowed.status).toBe(200);
      expect(allowed.headers.get("Cache-Control")).toBe("no-store");
      expect(await allowed.json()).toEqual(expect.arrayContaining([
        expect.objectContaining({subject:"inactive",role:"advisor",active:false,revision:1})
      ]));
      for(const actor of ["member","reader"]){
        expect((await handleMemberRequest(new Request(base),{DB:f.db},actor,"a","members")).status).toBe(403);
      }
      expect((await handleMemberRequest(new Request(base),{DB:f.db},"inactive","a","members")).status).toBe(404);
      expect((await handleMemberRequest(new Request(base),{DB:f.db},"absent","a","members")).status).toBe(404);
    }finally{f.close();}
  });

  it("POST grants, changes role and revokes with expected revision and replay responses",async()=>{
    const f=fixture();
    try {
      const action="/api/commissions/a/members";
      const granted=await handleMemberRequest(post(action,{
        subject:"newperson",role:"advisor",expectedRevision:null
      },"grant_api_12345"),{DB:f.db},"president","a","members");
      expect(granted.status).toBe(201);
      expect(await granted.json()).toMatchObject({
        subject:"newperson",role:"advisor",active:true,revision:1,replayed:false
      });
      const retry=await handleMemberRequest(post(action,{
        subject:"newperson",role:"advisor",expectedRevision:null
      },"grant_api_12345"),{DB:f.db},"president","a","members");
      expect(retry.status).toBe(200);
      expect(await retry.json()).toMatchObject({replayed:true,revision:1});

      const changed=await handleMemberRequest(post(action,{
        subject:"newperson",role:"member",expectedRevision:1
      },"role_api_12345"),{DB:f.db},"president","a","members");
      expect(changed.status).toBe(200);
      expect(await changed.json()).toMatchObject({role:"member",revision:2});

      const revoked=await handleMemberRequest(post(action+"/revoke",{
        subject:"newperson",expectedRevision:2
      },"revoke_api_12345"),{DB:f.db},"president","a","revoke");
      expect(revoked.status).toBe(200);
      expect(await revoked.json()).toMatchObject({active:false,revision:3});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:3});
    }finally{f.close();}
  });

  it("fails closed on cross-origin, self-revoke, stale state, extra fields, oversized body and unknown methods",async()=>{
    const f=fixture();
    try {
      const endpoint="/api/commissions/a/members";
      const revoke=endpoint+"/revoke";
      const env={DB:f.db};
      expect((await handleMemberRequest(post(endpoint,{subject:"outsider",role:"member",expectedRevision:null},
        "evil_origin_001","https://evil.example"),env,"president","a","members")).status).toBe(403);
      expect((await handleMemberRequest(post(endpoint,{subject:"other",role:"president",expectedRevision:null,actor:"president"},
        "extra_field_001"),env,"president","a","members")).status).toBe(400);
      expect((await handleMemberRequest(post(endpoint,{subject:"other",role:"member",expectedRevision:null},
        "small"),env,"president","a","members")).status).toBe(400);
      expect((await handleMemberRequest(post(endpoint,{subject:"x".repeat(9000),role:"member",expectedRevision:null},
        "oversize_req_001"),env,"president","a","members")).status).toBe(413);
      expect((await handleMemberRequest(post(revoke,{subject:"president",expectedRevision:1},
        "self_revoke_001"),env,"president","a","revoke")).status).toBe(403);
      expect((await handleMemberRequest(post(revoke,{subject:"member",expectedRevision:8},
        "stale_req_001"),env,"president","a","revoke")).status).toBe(409);
      expect((await handleMemberRequest(new Request(base,{method:"DELETE"}),env,"president","a","members")).status).toBe(405);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
});
