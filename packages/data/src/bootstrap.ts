import { validAccessSubject } from "./membership";

export class CommissionBootstrapInputError extends Error {}
export class CommissionBootstrapConflictError extends Error {}

export interface BootstrapInput {
  operatorSubject: string;
  initialPresidentSubject: string;
  name: string;
  requestKey: string;
}
export interface BootstrapResult {
  id: string;
  name: string;
  initialPresidentSubject: string;
  replayed: boolean;
}
interface BootstrapRecord {
  id: string;
  name: string;
  initialPresidentSubject: string;
  payloadHash: string;
}

async function digest(parts:string[]):Promise<string> {
  const bytes=new TextEncoder().encode(JSON.stringify(parts));
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))]
    .map(byte=>byte.toString(16).padStart(2,"0")).join("");
}
async function find(db:D1Database,input:BootstrapInput):Promise<BootstrapRecord|null> {
  return db.prepare(`
    SELECT commission_id AS id,name,initial_president_subject AS initialPresidentSubject,
      payload_sha256 AS payloadHash
    FROM commission_bootstrap_requests
    WHERE operator_subject=? AND request_key=?
  `).bind(input.operatorSubject,input.requestKey).first<BootstrapRecord>();
}

/**
 * Privileged data mutation. Must only be called after checking the verified
 * Access JWT sub equals a nonempty operator-only environment binding.
 * Never exposed to ordinary commission presidents.
 */
export async function createPilotCommission(
  db:D1Database,input:BootstrapInput
):Promise<BootstrapResult> {
  const name=typeof input.name==="string"?input.name.trim():"";
  if (!validAccessSubject(input.operatorSubject)
    || !validAccessSubject(input.initialPresidentSubject)
    || !/^[A-Za-z0-9_-]{8,96}$/.test(input.requestKey)
    || name.length<6 || name.length>160
    || /[\u0000-\u001f\u007f]/.test(input.name)) {
    throw new CommissionBootstrapInputError("Invalid pilot commission fields");
  }
  const hash=await digest([name,input.initialPresidentSubject]);
  const prior=await find(db,input);
  if (prior) {
    if (prior.payloadHash!==hash) {
      throw new CommissionBootstrapConflictError("Idempotency key used for another commission");
    }
    return {id:prior.id,name:prior.name,
      initialPresidentSubject:prior.initialPresidentSubject,replayed:true};
  }

  const id=crypto.randomUUID();
  try {
    const results=await db.batch([
      db.prepare(`
        INSERT INTO commissions(id,name)
        SELECT ?,? WHERE (
          SELECT COUNT(*) FROM commission_members
          WHERE subject=? AND active=1
        )<50
      `).bind(id,name,input.initialPresidentSubject),
      db.prepare(`
        INSERT INTO commission_bootstrap_requests(
          operator_subject,request_key,commission_id,name,
          initial_president_subject,payload_sha256
        ) SELECT ?,?,?,?,?,? WHERE changes()=1
      `).bind(input.operatorSubject,input.requestKey,id,name,
        input.initialPresidentSubject,hash),
      db.prepare(`
        INSERT INTO commission_members(commission_id,subject,role,active,revision)
        SELECT ?,?,'president',1,1 WHERE changes()=1
      `).bind(id,input.initialPresidentSubject),
      db.prepare(`
        INSERT INTO audit_events(
          id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json
        ) SELECT ?,?,?,'commission.created','commission',?,?
        WHERE changes()=1
      `).bind(crypto.randomUUID(),id,input.operatorSubject,id,
        JSON.stringify({initialPresidentSubject:input.initialPresidentSubject}))
    ]);
    if (results.some(row=>!row.success||row.meta.changes!==1)) {
      throw new CommissionBootstrapConflictError("Commission creation limit reached");
    }
  } catch(error) {
    const recorded=await find(db,input);
    if(recorded && recorded.payloadHash===hash) {
      return {id:recorded.id,name:recorded.name,
        initialPresidentSubject:recorded.initialPresidentSubject,replayed:true};
    }
    if(error instanceof CommissionBootstrapConflictError) throw error;
    throw new CommissionBootstrapConflictError("Bootstrap request conflicted or failed");
  }
  return {id,name,initialPresidentSubject:input.initialPresidentSubject,replayed:false};
}
