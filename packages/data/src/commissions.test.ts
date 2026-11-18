import { describe, expect, it, vi } from "vitest";
import { getCommissionSummary } from "./commissions";

describe("commission repository", () => {
  it("constrains lookup by both commission and authenticated subject", async () => {
    const first = vi.fn().mockResolvedValue({ id: "com_1", name: "Piloto", status: "active", role: "member" });
    const bind = vi.fn().mockReturnValue({ first });
    const prepare = vi.fn().mockReturnValue({ bind });
    const result = await getCommissionSummary({ prepare } as never, "user_1", "com_1");
    expect(result).toMatchObject({ id: "com_1", role: "member" });
    expect(bind).toHaveBeenCalledWith("com_1", "user_1");
    expect(prepare.mock.calls[0]?.[0]).toContain("m.active = 1");
    expect(prepare.mock.calls[0]?.[0]).toContain("m.subject = ?");
  });

  it("returns no data when the membership row is not available", async () => {
    const db = { prepare: () => ({ bind: () => ({ first: async () => null }) }) };
    await expect(getCommissionSummary(db as never, "user_a", "com_b")).resolves.toBeNull();
  });

  it("rejects empty identifiers before querying", async () => {
    const prepare = vi.fn();
    await expect(getCommissionSummary({ prepare } as never, "", "com_1")).rejects.toThrow();
    expect(prepare).not.toHaveBeenCalled();
  });
});

import { makeD1 } from "../../../tests/helpers/d1";
import { listAccessibleCommissions, listCommissionBatches } from "./commissions";

describe("membership-scoped discovery with SQLite", () => {
  function fixture() {
    const f = makeD1();
    f.sqlite.exec(`
      INSERT INTO commissions(id,name,status) VALUES
        ('c_a','Comisión A','active'), ('c_b','Comisión B','active'),
        ('c_closed','Comisión cerrada','closed');
      INSERT INTO commission_members(commission_id,subject,role,active) VALUES
        ('c_a','alice','member',1),('c_b','bob','president',1),
        ('c_closed','alice','observer',1), ('c_b','alice','member',0);
      INSERT INTO document_batches(id,commission_id,label) VALUES
        ('ba_1','c_a','Obras'),('bb_1','c_b','Contrataciones'),('bc_1','c_closed','Archivo');
    `);
    return f;
  }

  it("lists only actively assigned commissions without exposing revoked membership", async () => {
    const f = fixture();
    try {
      const rows = await listAccessibleCommissions(f.db, "alice");
      expect(rows.map(v=>v.id)).toEqual(["c_a","c_closed"]);
      expect(rows[0]).toMatchObject({role:"member",status:"active"});
      expect(rows[1]).toMatchObject({role:"observer",status:"closed"});
      expect(await listAccessibleCommissions(f.db, "unknown")).toEqual([]);
    } finally { f.close(); }
  });

  it("scopes batches to the selected commission and authenticated member", async () => {
    const f = fixture();
    try {
      expect(await listCommissionBatches(f.db,"alice","c_a")).toEqual([{id:"ba_1",label:"Obras"}]);
      expect(await listCommissionBatches(f.db,"alice","c_b")).toEqual([]);
      expect(await listCommissionBatches(f.db,"bob","c_b")).toEqual([{id:"bb_1",label:"Contrataciones"}]);
      expect(await listCommissionBatches(f.db,"alice","c_closed")).toEqual([{id:"bc_1",label:"Archivo"}]);
    } finally { f.close(); }
  });

  it("rejects empty identities without querying the database", async () => {
    const prepare = vi.fn();
    await expect(listAccessibleCommissions({prepare} as never,"")).rejects.toThrow();
    await expect(listCommissionBatches({prepare} as never,"","c_a")).rejects.toThrow();
    expect(prepare).not.toHaveBeenCalled();
  });
});
