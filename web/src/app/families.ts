// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Who } from "./session";

// The two families of finding a reader may hold apart. Dependency findings are
// what a scan of an inventory matched, and the flaws recorded beside them, read
// disclosed or undisclosed. Code findings are security testing work, read as
// one visibility.
type Family = "dependency" | "code";

// How a reader holds one family at one scope, which decides what a screen
// draws in place of its figures.
//
// - nowhere: no product they reach lets them read it; nothing about it is drawn.
// - elsewhere: they read it in another product and not this one; one line says
//   so, because a zero there reads as nothing being open.
// - here: they read all of it here; a zero is a real zero.
// - disclosed: they read only what has been disclosed in the products named;
//   every count is of those alone and says so.
export type Holding =
  | { held: "nowhere"; family: Family }
  | { held: "elsewhere"; family: Family; product: string }
  | { held: "here"; family: Family }
  | { held: "disclosed"; family: Family; only: string[]; all: boolean };

type Can = NonNullable<Who["reach"]>[number];

function reads(can: Can, family: Family): boolean {
  return family === "code" ? can.reads_security_testing : can.reads_public || can.reads_private;
}

// Security testing work is never disclosed, so only the dependency family has
// a disclosed half to be held alone.
function disclosedOnly(can: Can, family: Family): boolean {
  return family === "dependency" && can.reads_public && !can.reads_private;
}

// holding answers for one family at a product, or across every product the
// reader reaches where none is named. Derived from the session's answer alone:
// the server already narrows every count to what the reader holds, and this
// says which narrowing that was.
export function holding(who: Who | null | undefined, family: Family, product?: string): Holding {
  // Unread, the session says nothing yet, and the server has narrowed every
  // count already: the figures stand as they are until it answers.
  if (!who) return { held: "here", family };
  const reach = who.reach ?? [];
  const readers = reach.filter((can) => reads(can, family));
  if (readers.length === 0) return { held: "nowhere", family };
  if (product) {
    const named = product.toLowerCase();
    const can = readers.find((each) => each.product.toLowerCase() === named);
    if (!can) return { held: "elsewhere", family, product };
    return disclosedOnly(can, family)
      ? { held: "disclosed", family, only: [can.product], all: true }
      : { held: "here", family };
  }
  const only = readers.filter((can) => disclosedOnly(can, family)).map((can) => can.product);
  if (only.length === 0) return { held: "here", family };
  return { held: "disclosed", family, only, all: only.length === readers.length };
}

// Whether a screen draws this family's counts at all. A count is drawn where
// it means what it says: everything here, or disclosed work said to be that.
export function counted(at: Holding): boolean {
  return at.held === "here" || at.held === "disclosed";
}

// Whether the reader reads no finding of either family in any product: an
// auditor, an administrator holding no role, or a case collaborator.
export function readsNothing(who: Who | null | undefined): boolean {
  return (
    !!who &&
    holding(who, "dependency").held === "nowhere" &&
    holding(who, "code").held === "nowhere"
  );
}

const NOUN: Record<Family, string> = {
  dependency: "dependency findings",
  code: "code findings",
};

// The one line a screen shows in place of a figure, or beside it. Empty where
// the figure stands alone.
export function heldLine(at: Holding): string {
  switch (at.held) {
    case "nowhere":
      return `You don't read ${NOUN[at.family]} in any product.`;
    case "elsewhere":
      return `You don't read ${NOUN[at.family]} in ${at.product}.`;
    case "disclosed":
      return at.all
        ? "Counting disclosed findings, the ones you read here."
        : `Counting only disclosed findings in ${at.only.join(", ")}.`;
    case "here":
      return "";
  }
}
