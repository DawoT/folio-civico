import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { auditQuarantine } from "../../packages/data/src/quarantine-audit";

const runtime = exports as unknown as { default: { fetch(input: string): Promise<Response> } };
const bindings = env as unknown as { DOCUMENTS: R2Bucket; DB: D1Database };

describe("real local Workers runtime", () => {
  it("serves a non-sensitive health endpoint", async () => {
    const response = await runtime.default.fetch("https://worker.test/health");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({status:"ok"});
  });

  it("denies membership enumeration without a verified Access JWT", async () => {
    const response = await runtime.default.fetch("https://worker.test/api/commissions");
    expect(response.status).toBe(401);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("keeps a local R2 quarantine object private and retrievable only through the binding", async () => {
    const bucket = bindings.DOCUMENTS;
    const key = "quarantine/workerd-test-object.pdf";
    const original = new TextEncoder().encode("%PDF-1.7\n%%EOF");
    await bucket.put(key, original);
    try {
      const stored = await bucket.get(key);
      expect(stored).not.toBeNull();
      expect(new Uint8Array(await stored!.arrayBuffer())).toEqual(original);
      const response = await runtime.default.fetch("https://worker.test/"+key);
      expect(response.status).toBe(404);
    } finally {
      await bucket.delete(key);
    }
  });

  it("audits an R2 object using workerd LIST/HEAD without deleting or returning its key", async () => {
    const key="quarantine/workerd-reconciliation-synthetic.pdf";
    const bucket=bindings.DOCUMENTS;
    await bucket.put(key,new TextEncoder().encode("%PDF-1.7\n%%EOF"),{
      customMetadata:{sha256:"a".repeat(64)}
    });
    try {
      const emptyD1={
        prepare(_sql:string) {
          return {
            bind(..._values:unknown[]) {
              return {
                first:async()=>null,
                all:async()=>({results:[]})
              };
            }
          };
        }
      } as unknown as D1Database;
      const report=await auditQuarantine(emptyD1,bucket,{
        now:new Date(Date.now()+72*60*60*1000),
        pageSize:100,maxPages:1,maxReferences:10
      });
      expect(report.orphanCandidates).toBeGreaterThanOrEqual(1);
      expect(JSON.stringify(report)).not.toContain(key);
      expect(report.integrityVerified).toBe(false);
    } finally {
      // Test fixture cleanup, not the audit implementation.
      await bucket.delete(key);
    }
  });

  it("has an isolated D1 binding inside workerd", async () => {
    const result = await bindings.DB.prepare("SELECT 1 AS ok").first<{ok:number}>();
    expect(result?.ok).toBe(1);
  });
});
