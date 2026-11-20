import {afterEach,describe,expect,it,vi} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {revocationFixture} from "../../auth/src/revocation-fixture.test-helper";
import {syntheticOperatorAuthorization} from "../../auth/src/signed-fixture.test-helper";
import {
  registerRedriveRevocation,RevocationRegistrationAccessError,
  RevocationRegistrationConflictError
} from "./revocation-registration";
import {isManualRedriveRevoked} from "./redrive-revocations";

afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});

describe("R2.8 · private two-person audited revocation registration",()=>{
  it("atomically persists an immutable denylist entry and a matching incident journal",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const proof=await f.verify();
      const first=await registerRedriveRevocation(db.db,f.scope,proof);
      expect(first).toEqual({registered:true,replayed:false});
      expect(await registerRedriveRevocation(db.db,f.scope,proof))
        .toEqual({registered:true,replayed:true});
      expect(db.sqlite.prepare("SELECT kind,target,incident_ref AS incidentRef FROM processing_redrive_revocations").get())
        .toMatchObject({kind:f.scope.kind,target:f.scope.target,incidentRef:f.scope.incidentRef});
      const journal=db.sqlite.prepare(`
        SELECT actor_subject AS actor,approver_subject AS approver,request_key AS requestKey,
          payload_sha256 AS payload,reason_sha256 AS reason,
          approval_sha256 AS signedApproval
        FROM processing_redrive_revocation_actions
      `).get() as Record<string,string>;
      expect(journal).toMatchObject({
        actor:f.actor,approver:f.approver,requestKey:f.scope.requestKey,
        reason:proof.reasonHash,signedApproval:proof.approvalDigest
      });
      expect(journal.payload).toMatch(/^[0-9a-f]{64}$/);
      const data=JSON.stringify(db.sqlite.prepare("SELECT * FROM processing_redrive_revocation_actions").all());
      expect(data).not.toContain(f.scope.reason);
      expect(data).not.toContain(f.evidence.approvalJwt);
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocation_actions").get())
        .toMatchObject({n:1});
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_manual_redrives").get())
        .toMatchObject({n:0});
    }finally{db.close();}
  });

  it("rejects altered targets, reasons, tickets, reused keys and different incident approvals",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const proof=await f.verify();
      for(const mutation of [
        {target:"sha256:"+"e".repeat(64)},
        {reason:"Different legitimate incident rationale, but not approved by this signature."},
        {incidentRef:"INC_OTHER_20261119"},
        {requestKey:"another_key_0001"},
        {kind:"release_key" as never}
      ]){
        await expect(registerRedriveRevocation(db.db,{...f.scope,...mutation},proof))
          .rejects.toBeInstanceOf(RevocationRegistrationAccessError);
      }
      await expect(registerRedriveRevocation(db.db,f.scope,{...proof} as typeof proof))
        .rejects.toBeInstanceOf(RevocationRegistrationAccessError);
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
      await registerRedriveRevocation(db.db,f.scope,proof);
      const other=await revocationFixture({requestKey:f.scope.requestKey,reason:"An unrelated signed rationale with a different approval issuer timestamp."});
      const secondProof=await other.verify();
      await expect(registerRedriveRevocation(db.db,other.scope,secondProof))
        .rejects.toBeInstanceOf(RevocationRegistrationConflictError);
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
    }finally{db.close();}
  });

  it("allows exactly one independent operator to register the same global revocation",async()=>{
    const db=makeD1();
    try{
      const a=await revocationFixture({requestKey:"revocation_parallel_A"});
      const aProof=await a.verify();
      const b=await revocationFixture({requestKey:"revocation_parallel_B"});
      const bProof=await b.verify();
      const outcomes=await Promise.allSettled([
        registerRedriveRevocation(db.db,a.scope,aProof),
        registerRedriveRevocation(db.db,b.scope,bProof)
      ]);
      expect(outcomes.filter(x=>x.status==="fulfilled")).toHaveLength(1);
      expect(outcomes.filter(x=>x.status==="rejected")).toHaveLength(1);
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:1});
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocation_actions").get())
        .toMatchObject({n:1});
    }finally{db.close();}
  });

  it("denies raw unaudited inserts, journal tampering and rolls back an atomic D1 batch failure",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture();
      const proof=await f.verify();
      expect(()=>db.sqlite.prepare(`
        INSERT INTO processing_redrive_revocations(kind,target,incident_ref)
        VALUES(?,?,?)
      `).run(f.scope.kind,f.scope.target,f.scope.incidentRef))
        .toThrow(/REVOCATION_AUTHORIZATION_REQUIRED/);
      const wrapped={
        prepare:db.db.prepare.bind(db.db),
        batch:async()=>{throw new Error("D1 transaction unavailable");}
      } as unknown as D1Database;
      await expect(registerRedriveRevocation(wrapped,f.scope,proof))
        .rejects.toBeInstanceOf(RevocationRegistrationConflictError);
      expect(db.sqlite.prepare("SELECT count(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
      await registerRedriveRevocation(db.db,f.scope,proof);
      expect(()=>db.sqlite.exec("DELETE FROM processing_redrive_revocation_actions"))
        .toThrow(/REVOCATION_ACTION_IMMUTABLE/);
      expect(()=>db.sqlite.exec("UPDATE processing_redrive_revocation_actions SET actor_subject='forged'"))
        .toThrow(/REVOCATION_ACTION_IMMUTABLE/);
      expect(()=>db.sqlite.exec("UPDATE processing_redrive_revocations SET incident_ref='INC_FAKED_0001'"))
        .toThrow(/REDRIVE_REVOCATION_IMMUTABLE/);
    }finally{db.close();}
  });

  it("never treats an orphaned audit journal as a successful idempotent revocation",async()=>{
    const db=makeD1();
    try{
      const f=await revocationFixture({requestKey:"revocation_orphan_0001"});
      const proof=await f.verify();
      const parts=[
        f.scope.kind,f.scope.target,f.scope.incidentRef,f.scope.requestKey,
        proof.actorSubject,proof.approverSubject,
        proof.targetHash,proof.reasonHash,
        proof.approvalDigest,proof.approvalKeyThumbprint
      ];
      const digest=Array.from(new Uint8Array(await crypto.subtle.digest(
        "SHA-256",new TextEncoder().encode(JSON.stringify(parts))
      ))).map(x=>x.toString(16).padStart(2,"0")).join("");
      // A privileged SQL user might leave an orphan journal. Ordinary
      // operation must fail closed rather than report a false replay.
      db.sqlite.prepare(`
        INSERT INTO processing_redrive_revocation_actions(
          actor_subject,request_key,kind,target,incident_ref,
          approver_subject,target_sha256,reason_sha256,
          approval_sha256,approval_key_thumbprint,payload_sha256
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
      `).run(proof.actorSubject,f.scope.requestKey,f.scope.kind,f.scope.target,
        f.scope.incidentRef,proof.approverSubject,proof.targetHash,
        proof.reasonHash,proof.approvalDigest,proof.approvalKeyThumbprint,digest);
      await expect(registerRedriveRevocation(db.db,f.scope,proof))
        .rejects.toBeInstanceOf(RevocationRegistrationConflictError);
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
    }finally{db.close();}
  });

  it("rejects an incident capability that expires between journal lookup and the atomic write",async()=>{
    const db=makeD1();
    let clock:ReturnType<typeof vi.spyOn>|undefined;
    try{
      const f=await revocationFixture({requestKey:"revocation_expires_001"});
      const proof=await f.verify();
      const wrapped={
        prepare:(sql:string)=>{
          const statement=db.db.prepare(sql);
          if(!sql.includes("SELECT a.payload_sha256 AS payloadHash"))return statement;
          return {
            bind:(actor:string,key:string)=>({
              first:async()=>{
                const row=await statement.bind(actor,key).first();
                clock=vi.spyOn(Date,"now").mockReturnValue(proof.expiresAt+1000);
                return row;
              }
            })
          };
        },
        batch:db.db.batch.bind(db.db)
      } as unknown as D1Database;
      await expect(registerRedriveRevocation(wrapped,f.scope,proof))
        .rejects.toBeInstanceOf(RevocationRegistrationAccessError);
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocations").get())
        .toMatchObject({n:0});
      expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_redrive_revocation_actions").get())
        .toMatchObject({n:0});
    }finally{clock?.mockRestore();db.close();}
  });

  it("newly registered image revocation immediately blocks an existing signed redrive proof",async()=>{
    const db=makeD1();
    try{
      const existing=await syntheticOperatorAuthorization();
      const redriveProof=await existing.verify();
      expect(await isManualRedriveRevoked(db.db,redriveProof)).toBe(false);
      const f=await revocationFixture({target:redriveProof.imageDigest});
      const proof=await f.verify();
      await registerRedriveRevocation(db.db,f.scope,proof);
      expect(await isManualRedriveRevoked(db.db,redriveProof)).toBe(true);
    }finally{db.close();}
  });
});
