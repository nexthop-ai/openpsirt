// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { type ReactNode } from "react";

import { linkable } from "./addressable";

// An address from outside this deployment, as somewhere to click.
//
// The check is here rather than at each caller, because the failure this
// prevents is a caller that forgets: the guard was wired at two of the three
// screens that draw a person's "where the work is", and the third handed a
// typed `javascript:` straight to an `href` — a live link for the next person
// who opened the finding. Two of three is what a rule enforced by memory looks
// like.
//
// An address that fails the check is shown and not linked, so nothing
// disappears from the page: a reader still sees what was written, and can see
// that it is not an address.
export function Outward({
  href,
  children,
  className = "linkish",
  title,
  unlinked,
  lead,
}: {
  href: string | undefined | null;
  // The link's own text. The raw value is what a failed address falls back to,
  // whatever this is, unless `unlinked` says otherwise.
  children?: ReactNode;
  // Empty draws the link with no class of its own.
  className?: string;
  title?: string;
  // What is drawn where the address is missing or fails the check: where this
  // is left out, the raw value, or nothing for no address; nothing where it is
  // null.
  unlinked?: ReactNode;
  // What stands before the address wherever anything is drawn, such as a
  // separator in a line of facts.
  lead?: ReactNode;
}) {
  const at = linkable(href);
  const written = String(href ?? "");
  if (!written && unlinked === undefined) return null;
  if (!at) {
    if (unlinked === null) return null;
    return (
      <>
        {lead}
        {unlinked ?? <span className="id">{written}</span>}
      </>
    );
  }
  return (
    <>
      {lead}
      <a
        href={at}
        target="_blank"
        rel="noreferrer noopener"
        className={className || undefined}
        title={title}
      >
        {children ?? written}
      </a>
    </>
  );
}
