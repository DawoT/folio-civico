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
  commission: { id: "c_a", name: "A" },
  completeness: { included: 1, truncated: false },
  observations: [{ id: "o_a", status: "validated", evidence: [{type:"SEARCH_SCOPE"}] }]
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
});
