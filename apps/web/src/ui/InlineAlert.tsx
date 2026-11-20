import type { HTMLAttributes } from "react";

export type AlertTone = "error" | "success" | "info";
export interface InlineAlertProps extends Omit<HTMLAttributes<HTMLDivElement>, "role" | "aria-live"> {
  tone: AlertTone;
}

/** Errors are urgent; confirmations and neutral information are polite. */
export function InlineAlert({ tone, className, children, ...rest }: InlineAlertProps) {
  const classes = ["message", tone, className].filter(Boolean).join(" ");
  return (
    <div {...rest} className={classes} role={tone === "error" ? "alert" : "status"}
      aria-live={tone === "error" ? "assertive" : "polite"}>
      {children}
    </div>
  );
}
