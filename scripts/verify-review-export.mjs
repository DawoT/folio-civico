#!/usr/bin/env node
// Offline integrity check. SHA-256 is NOT an electronic signature or origin proof.
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

const FORMAT = "folio-civico.review-export.v1";
const MAX_FILE_BYTES = 9 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
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

export function verifyReviewExport(raw) {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_FILE_BYTES) {
    throw new Error("Invalid size");
  }
  const envelope = JSON.parse(raw);
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)
    || envelope.format !== FORMAT || typeof envelope.payload !== "string"
    || !/^[a-f0-9]{64}$/.test(envelope.sha256 ?? "")) {
    throw new Error("Invalid envelope");
  }
  const digest = createHash("sha256").update(envelope.payload, "utf8").digest("hex");
  if (digest !== envelope.sha256) {
    throw new Error("SHA-256 mismatch");
  }
  if (Buffer.byteLength(envelope.payload, "utf8") > MAX_PAYLOAD_BYTES) {
    throw new Error("Report exceeds safe payload limit");
  }
  const payload = JSON.parse(envelope.payload);
  const commission = payload?.commission;
  const completeness = payload?.completeness;
  const observations = payload?.observations;
  if (!object(payload) || payload.schemaVersion !== 1
    || payload.kind !== "internal_human_review"
    || !nonempty(payload.disclaimer) || !timestamp(payload.generatedAt, true)
    || !object(commission) || !nonempty(commission.id)
    || !nonempty(commission.name) || !["active", "closed"].includes(commission.status)
    || !object(completeness) || completeness.truncated !== false
    || completeness.maximumPerExport !== MAX_RECORDS
    || !Array.isArray(completeness.statuses)
    || completeness.statuses.length !== 2
    || !completeness.statuses.includes("validated")
    || !completeness.statuses.includes("dismissed")
    || !Array.isArray(observations) || observations.length > MAX_RECORDS
    || !Number.isSafeInteger(completeness.included)
    || completeness.included !== observations.length
    || !observations.every(item => validObservation(item, commission.id))
    || new Set(observations.map(item => item.id)).size !== observations.length) {
    throw new Error("Invalid report structure");
  }
  return {sha256: digest, count: observations.length};
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    if (process.argv.length !== 3 || statSync(process.argv[2]).size > MAX_FILE_BYTES) {
      throw new Error("Invalid file");
    }
    const result = verifyReviewExport(readFileSync(process.argv[2], "utf8"));
    console.log(`OK - SHA-256: ${result.sha256}; registros: ${result.count}`);
  } catch {
    console.error("INVALID - integridad o formato no verificado");
    process.exitCode = 2;
  }
}
