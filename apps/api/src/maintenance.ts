import { auditQuarantine, type QuarantineAuditOptions } from "@folio/data";

export interface AuditEnv {
  DB?: D1Database;
  DOCUMENTS?: R2Bucket;
}

export interface QuarantineAuditLog {
  kind: "folio.quarantine.audit";
  complete: boolean;
  scannedR2: number;
  scannedD1: number;
  referenced: number;
  orphanCandidates: number;
  recentUnreferenced: number;
  missingObjects: number;
  metadataMismatches: number;
  findingsTruncated: boolean;
  /** Not a verification of the physical bytes. */
  integrityVerified: false;
}

/**
 * Internal scheduled-only audit. No HTTP endpoint, mutations, file access or
 * raw R2 keys/filenames in logs. No cron is configured in Wrangler yet.
 */
export async function runQuarantineAudit(
  env: AuditEnv,
  emit: (summary: QuarantineAuditLog) => void,
  options: QuarantineAuditOptions = {}
): Promise<QuarantineAuditLog> {
  if (!env.DB || !env.DOCUMENTS) throw new Error("Quarantine bindings missing");
  const report = await auditQuarantine(env.DB, env.DOCUMENTS, options);
  const summary: QuarantineAuditLog = {
    kind: "folio.quarantine.audit",
    complete: report.complete,
    scannedR2: report.scannedR2,
    scannedD1: report.scannedD1,
    referenced: report.referenced,
    orphanCandidates: report.orphanCandidates,
    recentUnreferenced: report.recentUnreferenced,
    missingObjects: report.missingObjects,
    metadataMismatches: report.metadataMismatches,
    findingsTruncated: report.findingsTruncated,
    integrityVerified: false
  };
  emit(summary);
  return summary;
}
