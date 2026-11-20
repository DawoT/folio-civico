import type { HTMLAttributes } from "react";

type CardTag = "div" | "section" | "article";

export interface CardProps extends HTMLAttributes<HTMLElement> {
  as?: CardTag;
}

/** Preserve section landmarks and programmatic headings during adoption. */
export function Card({ as: Tag = "div", className, children, ...rest }: CardProps) {
  return <Tag {...rest} className={["fc-card", className].filter(Boolean).join(" ")}>{children}</Tag>;
}
