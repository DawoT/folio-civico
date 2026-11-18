export type MemberRole = "president" | "member" | "advisor" | "observer";
export type Permission = "read" | "draft" | "validate";

export interface Membership {
  commissionId: string;
  subject: string;
  role: MemberRole;
  active: boolean;
}

const grants: Record<MemberRole, ReadonlySet<Permission>> = {
  president: new Set(["read", "draft", "validate"]),
  member: new Set(["read", "draft", "validate"]),
  advisor: new Set(["read", "draft"]),
  observer: new Set(["read"])
};

/** Deny by default. Every operation must match a trusted identity and scope. */
export function assertMemberPermission(
  membership: Membership | null,
  subject: string,
  commissionId: string,
  permission: Permission
): void {
  if (!membership
    || !membership.active
    || !subject
    || !commissionId
    || membership.subject !== subject
    || membership.commissionId !== commissionId
    || !grants[membership.role]?.has(permission)) {
    throw new Error("Forbidden");
  }
}
