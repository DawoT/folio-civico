// Pure review-export v1 structure validation. Shared by the browser download
// gate and the independent Node CLI; no DOM, Node, network, or storage APIs.
const MAX_RECORDS = 500;

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonempty(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function timestamp(value, iso = false) {
  if (!nonempty(value)) return false;
  const date = new Date(value);
  return Number.isFinite(date.valueOf()) && (!iso || date.toISOString() === value);
}

function dateOnly(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(value + "T00:00:00.000Z");
  return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}

function validEvidence(value, commissionId) {
  if (!object(value) || value.commissionId !== commissionId) return false;
  switch (value.type) {
    case "SEARCH_SCOPE":
      return nonempty(value.checklistItemId) && nonempty(value.batchId)
        && nonempty(value.reviewerId) && timestamp(value.searchedAt, true);
    case "DOCUMENT_PAGE":
      return nonempty(value.documentVersionId)
        && Number.isSafeInteger(value.page) && value.page > 0
        && typeof value.sha256 === "string" && /^[a-f0-9]{64}$/i.test(value.sha256);
    case "OFFICIAL_SOURCE":
      return nonempty(value.source) && nonempty(value.sourceRecordId)
        && timestamp(value.consultedAt, true) && dateOnly(value.cutOffAt);
    default: return false;
  }
}

function validObservation(value, commissionId) {
  return object(value) && nonempty(value.id) && nonempty(value.authorSubject)
    && nonempty(value.title) && nonempty(value.description)
    && timestamp(value.createdAt)
    && (value.validatedBy === null || nonempty(value.validatedBy))
    && nonempty(value.reviewedBy) && value.reviewedBy !== value.authorSubject
    && timestamp(value.reviewedAt) && nonempty(value.reviewNote)
    && (value.status === "validated" || value.status === "dismissed")
    && Array.isArray(value.evidence)
    && value.evidence.every(item => validEvidence(item, commissionId));
}

/**
 * Validate structure only. This does NOT verify SHA-256, authenticate issuer,
 * or prove institutional origin; each caller must verify integrity separately.
 */
export function isValidReviewExportPayload(payload) {
  const commission = payload?.commission;
  const completeness = payload?.completeness;
  const observations = payload?.observations;
  return object(payload) && payload.schemaVersion === 1
    && payload.kind === "internal_human_review"
    && nonempty(payload.disclaimer) && timestamp(payload.generatedAt, true)
    && object(commission) && nonempty(commission.id)
    && nonempty(commission.name) && ["active", "closed"].includes(commission.status)
    && object(completeness) && completeness.truncated === false
    && completeness.maximumPerExport === MAX_RECORDS
    && Array.isArray(completeness.statuses)
    && completeness.statuses.length === 2
    && completeness.statuses.includes("validated")
    && completeness.statuses.includes("dismissed")
    && Array.isArray(observations) && observations.length <= MAX_RECORDS
    && Number.isSafeInteger(completeness.included)
    && completeness.included === observations.length
    && observations.every(item => validObservation(item, commission.id))
    && new Set(observations.map(item => item.id)).size === observations.length;
}
