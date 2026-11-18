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
