import type { MemberRole } from "@folio/domain";
import { getCommissionSummary } from "./commissions";

export class MembershipAccessError extends Error {}
export class MembershipConflictError extends Error {}
export class MembershipInputError extends Error {}

export interface CommissionMember {
  subject: string;
  role: MemberRole;
  active: boolean;
  revision: number;
}

export interface MembershipChangeInput {
  commissionId: string;
  actorSubject: string;
  memberSubject: string;
  expectedRevision: number | null;
  requestKey: string;
}
export interface GrantMemberInput extends MembershipChangeInput {
  role: MemberRole;
}
export interface MembershipChangeResult extends CommissionMember {
  replayed: boolean;
}

interface RequestRecord {
  memberSubject: string;
  operation: "grant" | "revoke";
  payloadSha256: string;
  resultRole: MemberRole;
  resultActive: number;
  resultRevision: number;
}

const ROLES: readonly MemberRole[] = ["president","member","advisor","observer"];
const VALID_KEY=/^[A-Za-z0-9_-]{8,96}$/;
const VALID_SUBJECT=/^[\x21-\x7E]{1,200}$/;
const MAX_MEMBERS=100;

/** Access subject is an opaque JWT sub, not an invitation email address. */
export function validAccessSubject(value: unknown): value is string {
  return typeof value==="string" && VALID_SUBJECT.test(value)
    && value===value.trim();
}

function requireInput(input: MembershipChangeInput): void {
  if (!validAccessSubject(input.memberSubject) || !validAccessSubject(input.actorSubject)
    || !VALID_KEY.test(input.requestKey)
    || (input.expectedRevision!==null &&
      (!Number.isSafeInteger(input.expectedRevision) || input.expectedRevision<1
        || input.expectedRevision>2147483646))) {
    throw new MembershipInputError("Invalid subject, revision or request key");
  }
}

async function authorize(db:D1Database,actor:string,commissionId:string):Promise<void> {
  const scope=await getCommissionSummary(db,actor,commissionId);
  if (!scope || scope.role!=="president") {
    throw new MembershipAccessError("An active commission president is required");
  }
  if (scope.status!=="active") {
    throw new MembershipConflictError("Commission is closed");
  }
}

async function fingerprint(parts:unknown[]):Promise<string> {
  const bytes=new TextEncoder().encode(JSON.stringify(parts));
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))]
    .map(byte=>byte.toString(16).padStart(2,"0")).join("");
}

async function findRequest(db:D1Database,input:MembershipChangeInput):Promise<RequestRecord|null> {
  return db.prepare(`
    SELECT member_subject AS memberSubject, operation,
      payload_sha256 AS payloadSha256, result_role AS resultRole,
      result_active AS resultActive, result_revision AS resultRevision
    FROM commission_member_actions
    WHERE commission_id=? AND actor_subject=? AND request_key=?
  `).bind(input.commissionId,input.actorSubject,input.requestKey).first<RequestRecord>();
}

function replay(record:RequestRecord):MembershipChangeResult {
  return {subject:record.memberSubject,role:record.resultRole,
    active:record.resultActive===1,revision:record.resultRevision,replayed:true};
}

async function mutate(
  db:D1Database,input:MembershipChangeInput,operation:"grant"|"revoke",
  requestedRole?:MemberRole
):Promise<MembershipChangeResult> {
  requireInput(input);
  if (operation==="grant" && !ROLES.includes(requestedRole as MemberRole)) {
    throw new MembershipInputError("Unsupported role");
  }
  if (operation==="revoke" && input.expectedRevision===null) {
    throw new MembershipInputError("Expected revision is required for revocation");
  }
  if (input.actorSubject===input.memberSubject) {
    throw new MembershipAccessError("Presidents cannot alter their own access");
  }

  await authorize(db,input.actorSubject,input.commissionId);
  const hash=await fingerprint([
    operation,input.memberSubject,requestedRole??null,input.expectedRevision
  ]);
  const prior=await findRequest(db,input);
  if(prior) {
    if (prior.payloadSha256!==hash || prior.operation!==operation
      || prior.memberSubject!==input.memberSubject) {
      throw new MembershipConflictError("Idempotency key belongs to another action");
    }
    return replay(prior);
  }

  // Explicit state check for role/revision on revocation. Mutations are still
  // rechecked with SQL predicates inside D1.batch to prevent TOCTOU.
  const current=await db.prepare(`
    SELECT role, active, revision
    FROM commission_members WHERE commission_id=? AND subject=?
  `).bind(input.commissionId,input.memberSubject)
    .first<{role:MemberRole;active:number;revision:number}>();

  if (operation==="grant") {
    if ((current===null)!==(input.expectedRevision===null)
      || (current && (current.revision!==input.expectedRevision
        || (current.active===1 && current.role===requestedRole)))) {
      throw new MembershipConflictError("Membership has changed or is already active");
    }
  } else if (!current || !current.active
    || current.revision!==input.expectedRevision) {
    throw new MembershipConflictError("Membership has changed or is inactive");
  }

  const role=operation==="grant"?requestedRole!:current!.role;
  const revision=(current?.revision??0)+1;
  const active=operation==="grant";
  const write=operation==="grant"
    ? db.prepare(`
      INSERT INTO commission_members(commission_id,subject,role,active,revision)
      SELECT c.id, ?, ?, 1, 1
      FROM commissions c
      JOIN commission_members actor ON actor.commission_id=c.id
      WHERE c.id=? AND c.status='active'
        AND actor.subject=? AND actor.role='president' AND actor.active=1
        AND actor.subject<>?
        AND (
          (? IS NULL AND NOT EXISTS(
            SELECT 1 FROM commission_members m WHERE m.commission_id=c.id AND m.subject=?
          ) AND (SELECT COUNT(*) FROM commission_members m WHERE m.commission_id=c.id) < ?)
          OR
          (? IS NOT NULL AND EXISTS(
            SELECT 1 FROM commission_members m
            WHERE m.commission_id=c.id AND m.subject=? AND m.revision=?
          ))
        )
      ON CONFLICT(commission_id,subject) DO UPDATE SET
        role=excluded.role, active=1, revision=commission_members.revision+1
      WHERE commission_members.revision=?
        AND (commission_members.active<>1 OR commission_members.role<>excluded.role)
    `).bind(input.memberSubject,role,input.commissionId,input.actorSubject,
      input.memberSubject,input.expectedRevision,input.memberSubject,MAX_MEMBERS,
      input.expectedRevision,input.memberSubject,input.expectedRevision,input.expectedRevision)
    : db.prepare(`
      UPDATE commission_members SET active=0,revision=revision+1
      WHERE commission_id=? AND subject=? AND active=1 AND revision=?
        AND subject<>?
        AND EXISTS (
          SELECT 1 FROM commissions c
          JOIN commission_members actor ON actor.commission_id=c.id
          WHERE c.id=? AND c.status='active' AND actor.subject=?
            AND actor.role='president' AND actor.active=1
        )
    `).bind(input.commissionId,input.memberSubject,input.expectedRevision,
      input.actorSubject,input.commissionId,input.actorSubject);

  // changes() ensures that the marker and audit never exist if the guarded
  // mutation changes zero rows; batch applies atomically in D1.
  try {
    const rows=await db.batch([
      write,
      db.prepare(`
        INSERT INTO commission_member_actions(
          commission_id,actor_subject,request_key,member_subject,
          operation,payload_sha256,result_role,result_active,result_revision
        )
        SELECT ?,?,?,?,?,?,?,?,? WHERE changes()=1
      `).bind(input.commissionId,input.actorSubject,input.requestKey,
        input.memberSubject,operation,hash,role,Number(active),revision),
      db.prepare(`
        INSERT INTO audit_events(
          id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json
        )
        SELECT ?,?,?,?,'commission_member',?,?
        WHERE changes()=1
      `).bind(crypto.randomUUID(),input.commissionId,input.actorSubject,
        operation==="grant"?"commission.member_granted":"commission.member_revoked",
        input.memberSubject,JSON.stringify({role,active,revision}))
    ]);
    if(rows.some(row=>!row.success || row.meta.changes!==1)) {
      throw new MembershipConflictError("Concurrent membership update was rejected");
    }
  } catch(error) {
    const saved=await findRequest(db,input);
    if(saved && saved.payloadSha256===hash && saved.memberSubject===input.memberSubject
      && saved.operation===operation) return replay(saved);
    if(error instanceof MembershipConflictError) throw error;
    throw new MembershipConflictError("Membership change failed or conflicted");
  }
  return {subject:input.memberSubject,role,active,revision,replayed:false};
}

export async function listCommissionMembers(
  db:D1Database,actorSubject:string,commissionId:string
):Promise<CommissionMember[]> {
  const summary=await getCommissionSummary(db,actorSubject,commissionId);
  if (!summary || summary.role!=="president") {
    throw new MembershipAccessError("Only active commission presidents can list members");
  }
  const rows=await db.prepare(`
    SELECT m.subject,m.role,m.active,m.revision
    FROM commission_members m
    JOIN commission_members actor ON actor.commission_id=m.commission_id
    WHERE m.commission_id=? AND actor.subject=? AND actor.active=1
      AND actor.role='president'
    ORDER BY m.active DESC, m.role ASC, m.subject ASC
    LIMIT ?
  `).bind(commissionId,actorSubject,MAX_MEMBERS+1).all<{
    subject:string;role:MemberRole;active:number;revision:number
  }>();
  if(rows.results.length===0) {
    // The actor may have lost their membership between the initial gate and SQL.
    throw new MembershipAccessError("Commission membership is no longer active");
  }
  if(rows.results.length>MAX_MEMBERS) {
    throw new MembershipConflictError("Membership list exceeds the supported limit");
  }
  return rows.results.map(row=>({...row,active:row.active===1}));
}

export async function grantCommissionMember(
  db:D1Database,input:GrantMemberInput
):Promise<MembershipChangeResult> {
  return mutate(db,input,"grant",input.role);
}
export async function revokeCommissionMember(
  db:D1Database,input:MembershipChangeInput
):Promise<MembershipChangeResult> {
  return mutate(db,input,"revoke");
}
