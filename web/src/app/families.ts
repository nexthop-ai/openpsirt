// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { statusOf } from "../api/queries";
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
// - partial: they read one half of the family alone, disclosed or undisclosed,
//   in the products named; every count is of what they read and says so.
//   `all` says every product counted is read that way.
type Half = "disclosed" | "undisclosed";
export type Holding =
  | { held: "nowhere"; family: Family }
  | { held: "elsewhere"; family: Family; product: string }
  | { held: "here"; family: Family }
  | { held: "partial"; family: Family; disclosed: string[]; undisclosed: string[]; all: boolean };

type Can = NonNullable<Who["reach"]>[number];

function reads(can: Can, family: Family): boolean {
  return family === "code" ? can.reads_security_testing : can.reads_public || can.reads_private;
}

// The half of the dependency family read alone, where only one is. Reading
// undisclosed work does not carry reading disclosed work, so either half may
// be held without the other. Security testing work is never disclosed, so the
// code family has no halves.
function halfOnly(can: Can, family: Family): Half | undefined {
  if (family !== "dependency" || can.reads_public === can.reads_private) return undefined;
  return can.reads_public ? "disclosed" : "undisclosed";
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
  // A product with no row is one the session does not list, a retired one
  // reached by a kept link most often: the server has narrowed its counts
  // already, so they stand, whatever the reader holds in the products listed.
  const row = product
    ? reach.find((each) => each.product.toLowerCase() === product.toLowerCase())
    : undefined;
  if (product && !row) return { held: "here", family };
  const readers = reach.filter((can) => reads(can, family));
  if (readers.length === 0) return { held: "nowhere", family };
  if (product && row) {
    if (!reads(row, family)) return { held: "elsewhere", family, product };
    const half = halfOnly(row, family);
    if (!half) return { held: "here", family };
    return {
      held: "partial",
      family,
      disclosed: half === "disclosed" ? [row.product] : [],
      undisclosed: half === "undisclosed" ? [row.product] : [],
      all: true,
    };
  }
  const halves = (half: Half) =>
    readers.filter((can) => halfOnly(can, family) === half).map((can) => can.product);
  const disclosed = halves("disclosed");
  const undisclosed = halves("undisclosed");
  if (disclosed.length + undisclosed.length === 0) return { held: "here", family };
  return {
    held: "partial",
    family,
    disclosed,
    undisclosed,
    // One half read alone in every product counted, so the line need name none.
    all: disclosed.length === readers.length || undisclosed.length === readers.length,
  };
}

// Whether a screen draws this family's counts at all. A count is drawn where
// it means what it says: everything here, or one half said to be that.
export function counted(at: Holding): boolean {
  return at.held === "here" || at.held === "partial";
}

// The holding a refused read of the family's counts says. A product the session
// does not list is held "here" until asked, and the server answers a reader who
// does not read the family there with 403: from then on it is held elsewhere,
// so one line stands where a zero would.
export function refusedAt(at: Holding, error: unknown, product: string): Holding {
  if (statusOf(error) !== 403 || !counted(at)) return at;
  return { held: "elsewhere", family: at.family, product };
}

// The holding one row's count of the family says, in a list spanning
// products. The server leaves a count out where the reader does not read the
// family in the row's product, which the session cannot say for a product it
// does not list.
export function answeredAt(at: Holding, present: boolean, product: string): Holding {
  if (present || !counted(at)) return at;
  return { held: "elsewhere", family: at.family, product };
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

// Whether the reader reads either family at the scope, which is where a report
// on triage decisions means anything: a decision is on a dependency finding or
// a code finding, and the server narrows each to the reader.
export function decidesAt(who: Who | null | undefined, product?: string): boolean {
  return counted(holding(who, "dependency", product)) || counted(holding(who, "code", product));
}

// The line a report on decisions shows in place of its body where the reader
// reads neither family at the scope. Empty where they read either.
export function decidesLine(who: Who | null | undefined, product?: string): string {
  if (decidesAt(who, product)) return "";
  return product && !readsNothing(who)
    ? `You don't read findings in ${product}.`
    : "You don't read findings in any product.";
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
    case "partial":
      if (at.all) {
        return at.disclosed.length > 0
          ? "Counting disclosed findings, the ones you read here."
          : "Counting undisclosed findings, the ones you read here.";
      }
      return `Counting ${[
        at.disclosed.length > 0 && `only disclosed findings in ${at.disclosed.join(", ")}`,
        at.undisclosed.length > 0 && `only undisclosed findings in ${at.undisclosed.join(", ")}`,
      ]
        .filter(Boolean)
        .join(", and ")}.`;
    case "here":
      return "";
  }
}

// Whether the reader reads undisclosed work at the product, or in some product
// where none is named: what vulnerability reports and the disclosure
// deadlines list. A product the session does not list is read as its rows,
// which the server has narrowed already.
export function readsUndisclosed(who: Who | null | undefined, product?: string): boolean {
  if (!who) return true;
  const reach = who.reach ?? [];
  if (product) {
    const named = product.toLowerCase();
    const row = reach.find((each) => each.product.toLowerCase() === named);
    return !row || row.reads_private;
  }
  return reach.some((each) => each.reads_private);
}

// The line a list of undisclosed work alone shows in place of its rows, such
// as the embargoes running out: empty where the reader reads undisclosed work
// at the scope.
export function undisclosedLine(who: Who | null | undefined, product?: string): string {
  if (readsUndisclosed(who, product)) return "";
  return product
    ? `You don't read undisclosed findings in ${product}.`
    : "You don't read undisclosed findings in any product.";
}
