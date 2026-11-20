import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const verifier = "scripts/verify-review-export.mjs";

function envelope(payload: object) {
  const serialized = JSON.stringify(payload);
  return JSON.stringify({
    format: "folio-civico.review-export.v1",
    sha256: createHash("sha256").update(serialized).digest("hex"),
    payload: serialized
  });
}

const valid = {
  schemaVersion: 1,
  kind: "internal_human_review",
  disclaimer: "Insumo de trabajo. No constituye acta oficial.",
  generatedAt: "2026-11-20T13:00:00.000Z",
  commission: { id: "c_a", name: "A", status: "active" },
  completeness: {
    included: 1, truncated: false, maximumPerExport: 500,
    statuses: ["validated", "dismissed"]
  },
  observations: [{
    id: "o_a", status: "validated", authorSubject: "author", title: "Revisión",
    description: "Observación documentada", createdAt: "2026-11-19 11:00:00",
    validatedBy: "reviewer", reviewedBy: "reviewer",
    reviewedAt: "2026-11-20 12:00:00",
    reviewNote: "Decisión humana sustentada",
    evidence: [{
      type: "SEARCH_SCOPE", commissionId: "c_a", checklistItemId: "item_1",
      batchId: "batch_1", reviewerId: "author",
      searchedAt: "2026-11-19T11:00:00.000Z"
    }]
  }]
};

function run(raw: string) {
  const dir = mkdtempSync(join(tmpdir(),"folio-export-"));
  try {
    const file = join(dir, "review.json");
    writeFileSync(file, raw, "utf8");
    return spawnSync(process.execPath, [verifier, file], {
      encoding: "utf8", timeout: 5000
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("independent offline review export verifier", () => {
  it("validates the exact payload bytes and reports their digest and record count", () => {
    const result = run(envelope(valid));
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/OK - SHA-256: [a-f0-9]{64}; registros: 1/);
  });

  it("rejects even a one-character modification of the payload", () => {
    const raw = envelope(valid);
    const modified = raw.replace("Comisión", "Otra"); // if absent, change the record title in raw below
    const changed = modified === raw ? raw.replace("o_a", "o_b") : modified;
    const result = run(changed);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("INVALID");
  });

  it("rejects correctly rehashed but invalid structure and unsupported pending decisions", () => {
    expect(run(envelope({...valid, observations:[{status:"draft"}]})).status).toBe(2);
    expect(run(envelope({...valid, completeness:{included:1,truncated:true}})).status).toBe(2);
    expect(run("not json").status).toBe(2);
  });

  it("rejects a rehashed report with missing review evidence, provenance or reviewer metadata", () => {
    for (const change of [
      { reviewedBy: "", reviewNote: "Decisión humana sustentada" },
      { reviewedBy: "reviewer", reviewNote: "" },
      { reviewedBy: "reviewer", createdAt: "invalid-date" },
      { reviewedBy: "reviewer", evidence: null },
      { reviewedBy: "reviewer", evidence: [{type:"SEARCH_SCOPE"}] }
    ]) {
      const observation = {...valid.observations[0], ...change};
      expect(run(envelope({...valid, observations:[observation]})).status).toBe(2);
    }
  });

  it("rejects cross-commission evidence and malformed document citations even with a valid hash", () => {
    const observation = valid.observations[0]!;
    for (const evidence of [
      {...observation.evidence[0], commissionId:"c_other"},
      {type:"DOCUMENT_PAGE",commissionId:"c_a",documentVersionId:"doc_1",page:0,
        sha256:"a".repeat(64)},
      {type:"DOCUMENT_PAGE",commissionId:"c_a",documentVersionId:"doc_1",page:1,
        sha256:"bad"},
      {type:"OFFICIAL_SOURCE",commissionId:"c_a",source:"public",sourceRecordId:"id_1",
        consultedAt:"bad",cutOffAt:"2026-11-19"}
    ]) {
      expect(run(envelope({...valid, observations:[{...observation,evidence:[evidence]}]})).status).toBe(2);
    }
  });

  it("rejects forged completeness metadata, repeated decisions and a report above 500 records", () => {
    const observation = valid.observations[0]!;
    for (const change of [
      { completeness:{...valid.completeness, statuses:["validated"]} },
      { completeness:{...valid.completeness, maximumPerExport:1000} },
      { commission:{...valid.commission,status:"unknown"} },
      { observations:[observation,observation],
        completeness:{...valid.completeness,included:2} },
      { observations:Array.from({length:501},(_,index)=>({...observation,id:`record_${index}`})),
        completeness:{...valid.completeness,included:501} }
    ]) {
      expect(run(envelope({...valid,...change})).status).toBe(2);
    }
  });

  it("accepts supported DOCUMENT_PAGE and OFFICIAL_SOURCE evidence with a valid full dossier", () => {
    for (const evidence of [
      {type:"DOCUMENT_PAGE",commissionId:"c_a",documentVersionId:"doc_1",page:1,
        sha256:"a".repeat(64)},
      {type:"OFFICIAL_SOURCE",commissionId:"c_a",source:"portal",sourceRecordId:"record_1",
        consultedAt:"2026-11-20T11:00:00.000Z",cutOffAt:"2026-11-19"}
    ]) {
      const observation={...valid.observations[0],evidence:[evidence]};
      expect(run(envelope({...valid,observations:[observation]})).status).toBe(0);
    }
  });

  it("accepts an empty but complete authorized export and the 500-record boundary", () => {
    expect(run(envelope({
      ...valid, observations:[], completeness:{...valid.completeness,included:0}
    })).status).toBe(0);
    const observations=Array.from({length:500},(_,index)=>({
      ...valid.observations[0],id:`record_${index}`
    }));
    expect(run(envelope({
      ...valid, observations, completeness:{...valid.completeness,included:500}
    })).status).toBe(0);
  });

  it("rejects an oversized payload even when the envelope is under its own size cap", () => {
    const oversized={...valid, observations:[{
      ...valid.observations[0],description:"x".repeat(8*1024*1024)
    }]};
    expect(run(envelope(oversized)).status).toBe(2);
  });

  it("rejects missing provenance dates and unsupported evidence types", () => {
    const observation=valid.observations[0]!;
    for (const change of [
      {generatedAt:"2026-02-30T00:00:00.000Z"},
      {disclaimer:""},
      {observations:[{...observation,evidence:[{
        ...observation.evidence[0],searchedAt:"2030-02-30T00:00:00.000Z"
      }]}]},
      {observations:[{...observation,evidence:[{
        ...observation.evidence[0],type:"UNVERIFIED_SOURCE"
      }]}]}
    ]) {
      expect(run(envelope({...valid,...change})).status).toBe(2);
    }
  });
});
