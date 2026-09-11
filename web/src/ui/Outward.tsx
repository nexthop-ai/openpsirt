import { type ReactNode } from "react";

import { linkable } from "./addressable";

// An address from outside this deployment, as somewhere to click.
//
// The judgment is here rather than at each caller, because the failure this
// prevents is a caller that forgets: the guard was wired at two of the three
// screens that draw a person's "where the work is", and the third handed a
// typed `javascript:` straight to an `href` — a live link for the next person
// who opened the finding. Two of three is what a rule enforced by memory looks
// like.
//
// What fails the judgment is shown and not linked, so nothing disappears from
// the page: a reader still sees what was written, and can see that it is not
// an address.
export function Outward({
  href,
  children,
  className = "linkish",
}: {
  href: string | undefined | null;
  // What the link says. The raw value is what a failed address falls back to,
  // whatever this is.
  children?: ReactNode;
  className?: string;
}) {
  const at = linkable(href);
  const written = String(href ?? "");
  if (!written) return null;
  if (!at) return <span className="id">{written}</span>;
  return (
    <a href={at} target="_blank" rel="noreferrer noopener" className={className}>
      {children ?? written}
    </a>
  );
}
