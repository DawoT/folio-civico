import { getCommissionSummary } from "./commissions";

export class ProvisioningAccessError extends Error {}
export class ProvisioningConflictError extends Error {}
export class ProvisioningInputError extends Error {}

interface BaseProvisioningInput {
  commissionId: string;
  subject: string;
  requestKey: string;
}

export interface CreateBatchInput extends BaseProvisioningInput { label: string; }
export interface CreateChecklistInput extends BaseProvisioningInput {
  area: "works" | "procurement";
  expectedDocument: string;
}

export interface CreatedBatch {
  id: string;
  label: string;
  replayed: boolean;
}

export interface CreatedChecklistItem {
  id: string;
  area: "works" | "procurement";
  expectedDocument: string;
  status: "pending";
  replayed: boolean;
}

type Operation = "batch" | "checklist";
type Resource = CreatedBatch | CreatedChecklistItem;

interface ProvisioningRecord {
  operation: Operation;
  payloadHash: string;
  resourceId: string;
}

function normalize(value: unknown, min: number, max: number): string {
  if (typeof value !== "string") throw new ProvisioningInputError("Expected text");
  const normalized = value.trim();
  if (normalized.length < min || normalized.length > max
    || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ProvisioningInputError("Text length or control characters invalid");
  }
  return normalized;
}

async function hashPayload(parts: string[]): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(JSON.stringify(parts))
  );
  return Array.from(new Uint8Array(digest), v => v.toString(16).padStart(2, "0")).join("");
}

async function findRequest(
  db: D1Database, input: BaseProvisioningInput
): Promise<ProvisioningRecord | null> {
  return db.prepare(`
    SELECT operation, payload_sha256 AS payloadHash, resource_id AS resourceId
    FROM commission_provisioning_requests
    WHERE commission_id=? AND actor_subject=? AND request_key=?
  `).bind(input.commissionId,input.subject,input.requestKey).first<ProvisioningRecord>();
}

async function readResource(
  db: D1Database, operation: Operation, id: string, commissionId: string,
  replayed: boolean
): Promise<Resource> {
  if (operation === "batch") {
    const row=await db.prepare(`
      SELECT id,label FROM document_batches WHERE id=? AND commission_id=?
    `).bind(id,commissionId).first<{id:string;label:string}>();
    if (!row) throw new ProvisioningConflictError("Provisioned batch unavailable");
    return {...row,replayed};
  }
  const row=await db.prepare(`
    SELECT id,area,expected_document AS expectedDocument,status
    FROM checklist_items WHERE id=? AND commission_id=?
  `).bind(id,commissionId).first<Omit<CreatedChecklistItem,"replayed">>();
  if (!row) throw new ProvisioningConflictError("Provisioned checklist item unavailable");
  return {...row,replayed};
}

async function authorizeProvisioning(db:D1Database,input:BaseProvisioningInput):Promise<void> {
  const membership=await getCommissionSummary(db,input.subject,input.commissionId);
  if (!membership || membership.role !== "president") {
    throw new ProvisioningAccessError("Only active presidents may provision records");
  }
  if (membership.status !== "active") {
    throw new ProvisioningConflictError("Commission is closed");
  }
}

async function authorizedResource(
  db:D1Database,input:BaseProvisioningInput,operation:Operation,id:string,replayed:boolean
):Promise<Resource> {
  const resource=await readResource(db,operation,id,input.commissionId,replayed);
  // Data, including the durable winner of a concurrent key claim, is read
  // asynchronously. Check the current president role after that final await.
  await authorizeProvisioning(db,input);
  return resource;
}

async function provision(
  db:D1Database, input:BaseProvisioningInput, operation:Operation,
  payloadParts:string[], label:string, area?: "works" | "procurement"
):Promise<Resource> {
  if (!/^[A-Za-z0-9_-]{8,96}$/.test(input.requestKey)) {
    throw new ProvisioningInputError("Invalid idempotency key");
  }
  await authorizeProvisioning(db,input);
  const payloadHash=await hashPayload([operation,...payloadParts]);
  const previous=await findRequest(db,input);
  if (previous) {
    if (previous.operation !== operation || previous.payloadHash !== payloadHash) {
      throw new ProvisioningConflictError("Idempotency key reused for another resource");
    }
    return authorizedResource(db,input,operation,previous.resourceId,true);
  }

  const id=crypto.randomUUID();
  // A NULL commission ID on failed authorization/limits aborts D1.batch,
  // so no provisioning marker or audit event can survive a failed write.
  const insert=operation==="batch"
    ? db.prepare(`
        INSERT INTO document_batches(id,commission_id,label)
        VALUES(?,(
          SELECT c.id FROM commissions c
          JOIN commission_members m ON m.commission_id=c.id
          WHERE c.id=? AND c.status='active' AND m.subject=? AND m.active=1
            AND m.role='president'
            AND (SELECT COUNT(*) FROM document_batches b WHERE b.commission_id=c.id)<100
        ),?)
      `).bind(id,input.commissionId,input.subject,label)
    : db.prepare(`
        INSERT INTO checklist_items(id,commission_id,area,expected_document)
        VALUES(?,(
          SELECT c.id FROM commissions c
          JOIN commission_members m ON m.commission_id=c.id
          WHERE c.id=? AND c.status='active' AND m.subject=? AND m.active=1
            AND m.role='president'
            AND (SELECT COUNT(*) FROM checklist_items i WHERE i.commission_id=c.id)<100
        ),?,?)
      `).bind(id,input.commissionId,input.subject,area!,label);

  try {
    const results=await db.batch([
      insert,
      db.prepare(`
        INSERT INTO commission_provisioning_requests(
          commission_id,actor_subject,request_key,operation,payload_sha256,resource_id
        ) VALUES(?,?,?,?,?,?)
      `).bind(input.commissionId,input.subject,input.requestKey,operation,payloadHash,id),
      db.prepare(`
        INSERT INTO audit_events(
          id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json
        ) VALUES(?,?,?,?,?,?,NULL)
      `).bind(crypto.randomUUID(),input.commissionId,input.subject,
        operation==="batch"?"commission.batch_created":"commission.checklist_item_created",
        operation==="batch"?"document_batch":"checklist_item",id)
    ]);
    if (results.some(row=>!row.success || row.meta.changes!==1)) {
      throw new ProvisioningConflictError("Provisioning transaction incomplete");
    }
  } catch {
    // Concurrent identical requests may lose the unique key race after both
    // attempted the insert. Re-read the durable winner before deciding.
    const replay=await findRequest(db,input);
    if (replay && replay.operation===operation && replay.payloadHash===payloadHash) {
      return authorizedResource(db,input,operation,replay.resourceId,true);
    }
    throw new ProvisioningConflictError("Provisioning rejected or request key in use");
  }
  return authorizedResource(db,input,operation,id,false);
}

export async function createCommissionBatch(
  db:D1Database,input:CreateBatchInput
):Promise<CreatedBatch> {
  const label=normalize(input.label,3,120);
  return provision(db,input,"batch",[label],label) as Promise<CreatedBatch>;
}

export async function createCommissionChecklistItem(
  db:D1Database,input:CreateChecklistInput
):Promise<CreatedChecklistItem> {
  if (input.area!=="works" && input.area!=="procurement") {
    throw new ProvisioningInputError("Invalid checklist area");
  }
  const expectedDocument=normalize(input.expectedDocument,3,160);
  return provision(db,input,"checklist",[input.area,expectedDocument],
    expectedDocument,input.area) as Promise<CreatedChecklistItem>;
}
