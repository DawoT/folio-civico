/**
 * Bounded, non-destructive reconciliation of private quarantine keys.
 *
 * Operator-only diagnostic. Do not expose this function as a public API or
 * infer that an orphan candidate is safe to delete. D1 and R2 are not a
 * transactional snapshot and a concurrent intake can temporarily diverge.
 */
export interface QuarantineAuditOptions {
  now?: Date;
  /** Always at least 48 hours to protect uploads in flight. */
  minAgeMs?: number;
  /** R2 pages, 1..5. */
  maxPages?: number;
  /** Objects requested per R2 page, 1..100. */
  pageSize?: number;
  /** Older D1 references checked via R2 HEAD, 1..250. */
  maxReferences?: number;
}
export type QuarantineFindingKind =
  | "orphan_candidate" | "missing_referenced_object" | "metadata_mismatch";

export interface QuarantineFinding {
  kind: QuarantineFindingKind;
  /** SHA-256-derived token; the private R2 key is deliberately not returned. */
  keyFingerprint: string;
}
export interface QuarantineAuditReport {
  startedAt: string;
  complete: boolean;
  integrityVerified: false;
  scannedR2: number;
  scannedD1: number;
  referenced: number;
  orphanCandidates: number;
  recentUnreferenced: number;
  missingObjects: number;
  metadataMismatches: number;
  findings: QuarantineFinding[];
  findingsTruncated: boolean;
  /** Explicit warning: no distributed snapshot of D1 and R2 is available. */
  snapshotAtomic: false;
}

const QUARANTINE_PREFIX="quarantine/";
const MINIMUM_GRACE_MS=48*60*60*1000;
const MAX_FINDINGS=25;

function boundedInteger(value:number | undefined,fallback:number,max:number,label:string):number {
  const selected=value??fallback;
  if (!Number.isInteger(selected) || selected<1 || selected>max) {
    throw new Error(`Invalid ${label}: expected integer 1..${max}`);
  }
  return selected;
}

async function fingerprint(key:string):Promise<string> {
  const hash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode("folio-r2-audit:"+key));
  return Array.from(new Uint8Array(hash).subarray(0,12),b=>b.toString(16).padStart(2,"0")).join("");
}

interface VersionRecord {
  objectKey:string;
  sha256:string;
}

/** Read-only reconciliation; never calls R2 get, put or delete. */
export async function auditQuarantine(
  db:D1Database,bucket:R2Bucket,options:QuarantineAuditOptions={}
):Promise<QuarantineAuditReport> {
  const now=options.now??new Date();
  if (!Number.isFinite(now.getTime())) throw new Error("Invalid audit timestamp");
  const minAgeMs=options.minAgeMs??MINIMUM_GRACE_MS;
  if(!Number.isSafeInteger(minAgeMs)||minAgeMs<MINIMUM_GRACE_MS) {
    throw new Error("Quarantine grace period cannot be below 48 hours");
  }
  const maxPages=boundedInteger(options.maxPages,3,5,"maxPages");
  const pageSize=boundedInteger(options.pageSize,50,100,"pageSize");
  const maxReferences=boundedInteger(options.maxReferences,100,250,"maxReferences");
  const cutoff=new Date(now.getTime()-minAgeMs);
  const report:QuarantineAuditReport={
    startedAt:now.toISOString(),complete:true,integrityVerified:false,
    scannedR2:0,scannedD1:0,referenced:0,orphanCandidates:0,
    recentUnreferenced:0,missingObjects:0,metadataMismatches:0,
    findings:[],findingsTruncated:false,snapshotAtomic:false
  };
  const noted=new Set<string>();
  async function finding(kind:QuarantineFindingKind,key:string):Promise<void> {
    const identity=kind+":"+key;
    if (noted.has(identity)) return;
    noted.add(identity);
    if (report.findings.length>=MAX_FINDINGS) {
      report.findingsTruncated=true;
      return;
    }
    report.findings.push({kind,keyFingerprint:await fingerprint(key)});
  }

  // Read D1 first. If the database is unavailable, do not issue a misleading
  // partial orphan inventory based only on bucket contents.
  const known=await db.prepare(`
    SELECT v.r2_object_key AS objectKey,v.sha256
    FROM document_versions v
    WHERE v.r2_object_key LIKE 'quarantine/%'
      AND datetime(v.created_at) <= datetime(?)
    ORDER BY v.created_at, v.id LIMIT ?
  `).bind(cutoff.toISOString(),maxReferences+1).all<VersionRecord>();
  const references=known.results.slice(0,maxReferences);
  report.scannedD1=references.length;
  if(known.results.length>maxReferences) report.complete=false;

  let cursor:string | undefined;
  for(let page=0;page<maxPages;page++){
    const result=await bucket.list({
      prefix:QUARANTINE_PREFIX,limit:pageSize,
      ...(cursor?{cursor}:{}),
      include:["customMetadata"]
    });
    for(const obj of result.objects) {
      // Never trust an unexpected key from an R2 listing response.
      if(!obj.key.startsWith(QUARANTINE_PREFIX)) throw new Error("Unexpected R2 list prefix");
      report.scannedR2++;
      const reference=await db.prepare(`
        SELECT v.r2_object_key AS objectKey,v.sha256
        FROM document_versions v WHERE v.r2_object_key=? LIMIT 1
      `).bind(obj.key).first<VersionRecord>();
      if(reference) {
        report.referenced++;
        if (obj.customMetadata?.sha256 && obj.customMetadata.sha256!==reference.sha256) {
          report.metadataMismatches++;
          await finding("metadata_mismatch",obj.key);
        }
      } else {
        const age=now.getTime()-new Date(obj.uploaded).getTime();
        if(Number.isFinite(age)&&age>=minAgeMs) {
          report.orphanCandidates++;
          await finding("orphan_candidate",obj.key);
        } else {
          // Unknown timestamps are also non-actionable.
          report.recentUnreferenced++;
        }
      }
    }
    if(!result.truncated) break;
    if(page===maxPages-1 || !result.cursor || result.cursor===cursor) {
      report.complete=false;
      break;
    }
    cursor=result.cursor;
  }

  // A D1 row can outlive an R2 object; the list alone cannot reveal this.
  // HEAD retrieves metadata only and never downloads or parses the original.
  for(const ref of references){
    const object=await bucket.head(ref.objectKey);
    if(!object) {
      report.missingObjects++;
      await finding("missing_referenced_object",ref.objectKey);
    } else if(object.customMetadata?.sha256 && object.customMetadata.sha256!==ref.sha256
      && !noted.has("metadata_mismatch:"+ref.objectKey)) {
      report.metadataMismatches++;
      await finding("metadata_mismatch",ref.objectKey);
    }
  }
  return report;
}
