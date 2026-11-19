import type { HTMLAttributes } from "react";

type FeedbackProps = HTMLAttributes<HTMLParagraphElement>;

/** Text announces loading: no spinner-only progress or invented result. */
export function LoadingState({ className, children, ...rest }: FeedbackProps) {
  return (
    <p {...rest} className={["empty", "fc-loading", className].filter(Boolean).join(" ")}
      role="status" aria-live="polite">{children}</p>
  );
}

/** Empty results are neutral; they are never presented as a verified absence. */
export function EmptyState({ className, children, ...rest }: FeedbackProps) {
  return (
    <p {...rest} className={["empty", "fc-empty", className].filter(Boolean).join(" ")}
      role="status" aria-live="polite">{children}</p>
  );
}
