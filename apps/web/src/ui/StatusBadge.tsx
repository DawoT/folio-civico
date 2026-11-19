import type { HTMLAttributes } from "react";

/** Workflow-facing states. A document marked ready is not an official approval. */
export type BadgeStatus =
  | "neutral" | "warning" | "error" | "success"
  | "quarantined" | "processing" | "ready" | "reviewing"
  | "validated" | "dismissed";

export interface StatusBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  status: BadgeStatus;
}

/** Always supply visible status text: meaning must not rely on color alone. */
export function StatusBadge({ status, className, children, ...rest }: StatusBadgeProps) {
  return (
    <span {...rest}
      className={["status-badge", `status-badge--${status}`, className].filter(Boolean).join(" ")}>
      {children}
    </span>
  );
}
