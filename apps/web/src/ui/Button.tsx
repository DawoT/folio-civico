import type { ButtonHTMLAttributes } from "react";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary";
  /** Prevent duplicate actions and expose the busy state to assistive tech. */
  busy?: boolean;
}

/**
 * Semantic, keyboard-native button. Explicit default type avoids accidental
 * form submissions. Retains legacy classes during gradual migration.
 */
export function Button({
  variant = "secondary", busy = false, disabled = false,
  type = "button", className, children, ...rest
}: ButtonProps) {
  const classes = ["button", variant, className].filter(Boolean).join(" ");
  return (
    <button {...rest} type={type} className={classes} disabled={disabled || busy}
      aria-busy={busy || undefined}>
      {children}
    </button>
  );
}
