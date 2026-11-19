import type { SavedObservation } from "./review";

export class ObservationCursorError extends Error {}

export interface ObservationPage {
  items: SavedObservation[];
  nextCursor: string | null;
}
export interface ObservationPageOptions {
  cursor?: string | null;
  limit?: number;
}

const MAX_PAGE_SIZE = 50;
const DEFAULT_PAGE_SIZE = 25;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const CREATED_AT = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,3}Z?)?$/;
interface CursorData {v:number; c:string; t:string; id:string}

function encodeCursor(commissionId:string, createdAt:string, id:string):string {
  const json=JSON.stringify({v:1,c:commissionId,t:createdAt,id});
  return btoa(json).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

function parseCursor(value:string | null | undefined, commissionId:string):
{createdAt:string;id:string} | null {
  if(value===null || value===undefined) return null;
  if(!/^[A-Za-z0-9_-]{12,512}$/.test(value)) {
    throw new ObservationCursorError("Cursor format invalid");
  }
  try {
    const payload=JSON.parse(atob(value.replace(/-/g,"+").replace(/_/g,"/")
      + "=".repeat((4-value.length%4)%4))) as CursorData;
    if(!payload || typeof payload!=="object" || Array.isArray(payload)
      || Object.keys(payload).sort().join(",")!=="c,id,t,v"
      || payload.v!==1 || payload.c!==commissionId
      || typeof payload.t!=="string" || !CREATED_AT.test(payload.t)
      || typeof payload.id!=="string" || !ID.test(payload.id)
      || encodeCursor(payload.c,payload.t,payload.id)!==value) {
      throw new Error("Invalid cursor contents");
    }
    return {createdAt:payload.t,id:payload.id};
  } catch {
    throw new ObservationCursorError("Cursor format or commission invalid");
  }
}

type PageRow = Omit<SavedObservation, "evidence"> & {
  evidenceJson: string | null;
  submitFlag: number;
  reviewFlag: number;
};

/**
 * Stable keyset pagination. Bound to a single commission and a currently
 * active membership; cursor carries no authorization or secret.
 */
export async function listObservationPage(
  db:D1Database,subject:string,commissionId:string,options:ObservationPageOptions={}
):Promise<ObservationPage> {
  if(!subject || !commissionId || !ID.test(commissionId)) {
    return {items:[],nextCursor:null};
  }
  const limit=options.limit??DEFAULT_PAGE_SIZE;
  if(!Number.isSafeInteger(limit)||limit<1||limit>MAX_PAGE_SIZE) {
    throw new ObservationCursorError("Invalid page size");
  }
  const anchor=parseCursor(options.cursor,commissionId);
  const result=await db.prepare(`
    WITH chosen AS (
      SELECT o.id,o.created_at
      FROM observations o
      JOIN commission_members m ON m.commission_id=o.commission_id
        AND m.subject=? AND m.active=1
      WHERE o.commission_id=?
        AND (? IS NULL OR o.created_at < ? OR
          (o.created_at=? AND o.id < ?))
      ORDER BY o.created_at DESC,o.id DESC
      LIMIT ?
    )
    SELECT o.id,o.commission_id AS commissionId,
      o.author_subject AS authorSubject,o.title,o.description,o.status,
      o.validated_by AS validatedBy,o.created_at AS createdAt,
      o.reviewed_by AS reviewedBy,o.reviewed_at AS reviewedAt,
      o.review_note AS reviewNote,
      CASE WHEN o.status='draft' AND o.author_subject=m.subject
        AND m.role IN ('president','member','advisor') AND c.status='active'
        THEN 1 ELSE 0 END AS submitFlag,
      CASE WHEN o.status='in_review' AND o.author_subject<>m.subject
        AND m.role IN ('president','member') AND c.status='active'
        THEN 1 ELSE 0 END AS reviewFlag,
      e.reference_json AS evidenceJson
    FROM chosen picked
    JOIN observations o ON o.id=picked.id AND o.commission_id=?
    JOIN commission_members m ON m.commission_id=o.commission_id
      AND m.subject=? AND m.active=1
    JOIN commissions c ON c.id=o.commission_id
    LEFT JOIN observation_evidence e ON e.observation_id=o.id
    ORDER BY picked.created_at DESC,picked.id DESC,e.created_at ASC,e.id ASC
  `).bind(subject,commissionId,anchor?.createdAt??null,anchor?.createdAt??null,
    anchor?.createdAt??null,anchor?.id??null,limit+1,
    commissionId,subject).all<PageRow>();
  const grouped=new Map<string,SavedObservation>();
  for(const row of result.results) {
    let record=grouped.get(row.id);
    if(!record) {
      record={
        id:row.id,commissionId:row.commissionId,authorSubject:row.authorSubject,
        title:row.title,description:row.description,status:row.status,
        validatedBy:row.validatedBy,createdAt:row.createdAt,
        reviewedBy:row.reviewedBy??null,reviewedAt:row.reviewedAt??null,
        reviewNote:row.reviewNote??null,
        canSubmit:row.submitFlag===1,canReview:row.reviewFlag===1,evidence:[]
      };
      grouped.set(row.id,record);
    }
    if(row.evidenceJson) record.evidence.push(JSON.parse(row.evidenceJson));
  }
  const records=[...grouped.values()];
  const items=records.slice(0,limit);
  const last=items[items.length-1];
  return {
    items,
    nextCursor:records.length>limit && last
      ?encodeCursor(commissionId,last.createdAt,last.id):null
  };
}
