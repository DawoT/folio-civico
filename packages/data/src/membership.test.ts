import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {afterFirstRead,aroundBatch} from "../../../tests/helpers/d1-write-replay-race";
import {
  listCommissionMembers,grantCommissionMember,revokeCommissionMember,
  MembershipAccessError,MembershipConflictError,MembershipInputError
} from "./membership";
import {getCommissionSummary} from "./commissions";

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('a','Comisión A','active'),('b','Comisión B','active'),('closed','Cerrada','closed');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('a','president','president',1),('a','other_president','president',1),
      ('a','member','member',1),('a','inactive','observer',0),
      ('a','observer','observer',1),('b','foreign','president',1),
      ('closed','president','president',1);
  `);
  return f;
}
const base={commissionId:"a",actorSubject:"president",requestKey:"request_grant_001"};
const target={...base,memberSubject:"new_member",role:"advisor" as const,expectedRevision:null};

describe("commission member lifecycle",()=>{
  it.each(["revoked","demoted","closed"] as const)(
    "does not replay an existing membership action after the actor becomes %s during journal lookup",
    async(change)=>{
      const f=fixture();
      try{
        await grantCommissionMember(f.db,target);
        const raced=afterFirstRead(f.db,"FROM commission_member_actions",()=>{
          if(change==="revoked") {
            f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='a' AND subject='president'");
          } else if(change==="demoted") {
            f.sqlite.exec("UPDATE commission_members SET role='member' WHERE commission_id='a' AND subject='president'");
          } else {
            f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='a'");
          }
        });
        await expect(grantCommissionMember(raced,target)).rejects.toBeInstanceOf(
          change==="closed"?MembershipConflictError:MembershipAccessError
        );
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_member_actions").get()).toEqual({n:1});
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
      } finally {f.close();}
    }
  );

  it("does not acknowledge an idempotent winner if the actor is revoked before the batch conflict recovery",async()=>{
    const f=fixture();
    try {
      const raced=aroundBatch(f.db,async()=>{
        await grantCommissionMember(f.db,target);
        f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='a' AND subject='president'");
        throw new Error("SYNTHETIC_CONCURRENT_KEY_CLAIM");
      });
      await expect(grantCommissionMember(raced,target)).rejects.toBeInstanceOf(MembershipAccessError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_member_actions").get()).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
  });

  it("does not acknowledge a committed membership mutation if the actor loses authority after D1.batch",async()=>{
    const f=fixture();
    try{
      const raced=aroundBatch(f.db,async statements=>{
        const results=await f.db.batch(statements);
        f.sqlite.exec("UPDATE commission_members SET role='observer' WHERE commission_id='a' AND subject='president'");
        return results;
      });
      await expect(grantCommissionMember(raced,target)).rejects.toBeInstanceOf(MembershipAccessError);
      // The already committed D1 transaction is not rolled back by a response fence.
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_member_actions").get()).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
  });


  it("lists only within one commission for an active president, including inactive members and revisions",async()=>{
    const f=fixture();
    try {
      const rows=await listCommissionMembers(f.db,"president","a");
      expect(rows).toEqual(expect.arrayContaining([
        expect.objectContaining({subject:"inactive",role:"observer",active:false,revision:1}),
        expect.objectContaining({subject:"president",role:"president",active:true,revision:1})
      ]));
      for(const actor of ["member","observer","inactive","foreign","absent"]){
        await expect(listCommissionMembers(f.db,actor,"a")).rejects.toBeInstanceOf(MembershipAccessError);
      }
      expect(await listCommissionMembers(f.db,"foreign","b")).toHaveLength(1);
    }finally{f.close();}
  });
  it("adds, promotes, revokes and restores membership with CAS revisions and immutable audit",async()=>{
    const f=fixture();
    try {
      const created=await grantCommissionMember(f.db,target);
      expect(created).toMatchObject({subject:"new_member",role:"advisor",active:true,revision:1,replayed:false});
      const promotion=await grantCommissionMember(f.db,{
        ...target,role:"president",expectedRevision:1,requestKey:"request_promote_001"
      });
      expect(promotion).toMatchObject({role:"president",revision:2});
      const revoked=await revokeCommissionMember(f.db,{
        ...base,memberSubject:"new_member",expectedRevision:2,requestKey:"request_revoke_001"
      });
      expect(revoked).toMatchObject({active:false,role:"president",revision:3});
      expect(await getCommissionSummary(f.db,"new_member","a")).toBeNull();
      const restored=await grantCommissionMember(f.db,{
        ...target,role:"member",expectedRevision:3,requestKey:"request_restore_001"
      });
      expect(restored).toMatchObject({active:true,role:"member",revision:4});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:4});
      const events=f.sqlite.prepare("SELECT action,resource_id AS resourceId FROM audit_events ORDER BY created_at,id").all();
      expect(events.map(e=>e.action).sort()).toEqual([
        "commission.member_granted","commission.member_granted",
        "commission.member_granted","commission.member_revoked"
      ]);
      expect(events.every(e=>e.resourceId==="new_member")).toBe(true);
    } finally {f.close();}
  });
  it("replays exact requests, rejects reused keys and stale revisions without mutating",async()=>{
    const f=fixture();
    try {
      const created=await grantCommissionMember(f.db,target);
      expect(await grantCommissionMember(f.db,target)).toMatchObject({...created,replayed:true});
      await expect(grantCommissionMember(f.db,{...target,role:"member"}))
        .rejects.toBeInstanceOf(MembershipConflictError);
      await expect(grantCommissionMember(f.db,{...target,requestKey:"stale_key_001",role:"member",expectedRevision:null}))
        .rejects.toBeInstanceOf(MembershipConflictError);
      await expect(revokeCommissionMember(f.db,{
        ...base,memberSubject:"new_member",expectedRevision:99,requestKey:"wrong_revision_01"
      })).rejects.toBeInstanceOf(MembershipConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_member_actions").get()).toMatchObject({n:1});
    }finally{f.close();}
  });
  it("denies unauthorized, revoked, self-modification, cross-tenant and closed commission writes",async()=>{
    const f=fixture();
    try {
      for(const actor of ["member","observer","inactive","foreign","absent"]){
        await expect(grantCommissionMember(f.db,{...target,actorSubject:actor,requestKey:"attempt_"+actor}))
          .rejects.toBeInstanceOf(MembershipAccessError);
      }
      await expect(grantCommissionMember(f.db,{...target,memberSubject:"president",expectedRevision:1}))
        .rejects.toBeInstanceOf(MembershipAccessError);
      await expect(revokeCommissionMember(f.db,{...base,memberSubject:"president",expectedRevision:1}))
        .rejects.toBeInstanceOf(MembershipAccessError);
      await expect(grantCommissionMember(f.db,{...target,commissionId:"closed"}))
        .rejects.toBeInstanceOf(MembershipConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
  it("cannot remove final active president or change membership in inactive commission",async()=>{
    const f=fixture();
    try {
      await revokeCommissionMember(f.db,{...base,memberSubject:"other_president",
        expectedRevision:1,requestKey:"revoke_second_01"});
      const rows=await listCommissionMembers(f.db,"president","a");
      expect(rows.filter(m=>m.active&&m.role==="president")).toHaveLength(1);
      await expect(revokeCommissionMember(f.db,{...base,memberSubject:"president",
        expectedRevision:1,requestKey:"revoke_final_001"})).rejects.toBeInstanceOf(MembershipAccessError);
      expect((await getCommissionSummary(f.db,"president","a"))?.role).toBe("president");
    }finally{f.close();}
  });
  it("prohibits editing or deleting the immutable membership request journal",async()=>{
    const f=fixture();
    try {
      await grantCommissionMember(f.db,target);
      expect(()=>f.sqlite.exec("UPDATE commission_member_actions SET result_active=0"))
        .toThrow(/MEMBERSHIP_ACTION_IMMUTABLE/);
      expect(()=>f.sqlite.exec("DELETE FROM commission_member_actions"))
        .toThrow(/MEMBERSHIP_ACTION_IMMUTABLE/);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:1});
    }finally{f.close();}
  });

  it("rejects control characters, invalid roles, zero revisions and a 101st member",async()=>{
    const f=fixture();
    try {
      await expect(grantCommissionMember(f.db,{...target,memberSubject:"  bad\nuser"}))
        .rejects.toBeInstanceOf(MembershipInputError);
      await expect(grantCommissionMember(f.db,{...target,role:"superadmin" as "president"}))
        .rejects.toBeInstanceOf(MembershipInputError);
      await expect(grantCommissionMember(f.db,{...target,expectedRevision:0}))
        .rejects.toBeInstanceOf(MembershipInputError);
      for(let i=0;i<96;i++) f.sqlite.prepare(
        "INSERT INTO commission_members(commission_id,subject,role,active) VALUES('a',?,'member',1)"
      ).run("seed_"+i);
      await expect(grantCommissionMember(f.db,target)).rejects.toBeInstanceOf(MembershipConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_member_actions").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
});
