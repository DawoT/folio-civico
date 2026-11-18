import { describe, expect, it } from "vitest";
import { assertMemberPermission } from "./permissions";

describe("commission authorization", () => {
  const member = { commissionId: "com_a", subject: "user_a", role: "member", active: true } as const;

  it("allows an active member to read the same commission", () => {
    expect(() => assertMemberPermission(member, "user_a", "com_a", "read")).not.toThrow();
  });

  it("blocks access to another commission even when its ID is known", () => {
    expect(() => assertMemberPermission(member, "user_a", "com_b", "read")).toThrow();
  });

  it("blocks impersonation and inactive accounts", () => {
    expect(() => assertMemberPermission(member, "user_b", "com_a", "read")).toThrow();
    expect(() => assertMemberPermission({ ...member, active: false }, "user_a", "com_a", "read")).toThrow();
  });

  it("prevents advisers from validating decisions", () => {
    expect(() => assertMemberPermission({ ...member, role: "advisor" }, "user_a", "com_a", "validate")).toThrow();
  });

  it("does not grant access on absent membership", () => {
    expect(() => assertMemberPermission(null, "user_a", "com_a", "read")).toThrow();
  });
});
