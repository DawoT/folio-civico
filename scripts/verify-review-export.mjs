#!/usr/bin/env node
// Offline integrity check. SHA-256 is NOT an electronic signature or origin proof.
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { isValidReviewExportPayload } from "../packages/domain/src/review-export-structure.mjs";

const FORMAT = "folio-civico.review-export.v1";
const MAX_FILE_BYTES = 9 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
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
  if (!isValidReviewExportPayload(payload)) {
    throw new Error("Invalid report structure");
  }
  return {sha256: digest, count: payload.observations.length};
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
