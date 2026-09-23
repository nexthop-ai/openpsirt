// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// What the advisory screens work out, apart from what draws them.

// The editorial statuses, with the word on screen and what reaching it means.
//
// The three are the standard's own, so they are shown under their own names
// rather than translated. What each is underneath them, because "interim" is
// not a word whose meaning a reader guesses.
const said: Record<string, { label: string; tone: string; means: string }> = {
  draft: {
    label: "Draft",
    tone: "",
    means: "Nobody has agreed to what it says, and it has not gone out",
  },
  final: {
    label: "Final",
    tone: "agreed",
    means: "Somebody has agreed to what it says now",
  },
  // Not "it has changed since". A withdrawn agreement reaches this with
  // nothing a reader acts on having moved.
  interim: {
    label: "Interim",
    tone: "waiting",
    means: "It has gone out, and nobody agrees to what it says now",
  },
};

// This table's entry for a word, or nothing.
//
// Asked through a guard rather than by indexing: an object literal inherits
// from the prototype, so a server-supplied word naming a member of it —
// `constructor`, `toString` — comes back as a function, and the optional
// chain that guards the lookup does not guard the field read after it.
export function standing(status?: string): (typeof said)[string] | undefined {
  const word = status ?? "";
  return Object.hasOwn(said, word) ? said[word] : undefined;
}

// The status as a reader sees it. A word this table does not know is shown as
// it arrived, so a server that grows one before the interface does leaves
// somebody reading something unfamiliar rather than a blank.
export function statusLabel(status?: string): string {
  return standing(status)?.label ?? status ?? "";
}

// Who agrees to what an advisory says now, as a sentence opens.
//
// A count beside a status word is the shape this replaces: "1 agree" is
// wrong, and a bare number beside a chip saying Final is a figure nobody
// reads.
export function agreeing(people: number): string {
  if (people <= 0) return "Nobody agrees";
  if (people === 1) return "One person agrees";
  return `${people} people agree`;
}

// What has to happen before an advisory can go out.
export type Missing = "" | "flaws" | "agreement";

// Nothing named comes first: an advisory covering no flaw generates no
// document at all, so an agreement is not the next thing to go looking for.
export function missing(covers: number, agreed: number): Missing {
  if (covers <= 0) return "flaws";
  if (agreed <= 0) return "agreement";
  return "";
}

// One flaw somebody may name on this advisory, and whether it is fixed
// wherever it was found.
export type Nameable = { vulnerability: string; summary: string; fixed: boolean };

// The flaws recorded in a product that this advisory does not already name
// there.
//
// A flaw arriving twice is offered once. Already covered is per product: the
// pair is what an advisory names, and the same issue in a second product is a
// second thing to say. A row that does not say how much of it is open is not
// called fixed.
export function nameable(
  rows: readonly { vulnerability?: string; summary?: string; open?: number }[],
  covers: readonly { product?: string; vulnerability?: string }[],
  product: string,
): Nameable[] {
  const already = new Set(
    covers.filter((one) => one.product === product).map((one) => one.vulnerability ?? ""),
  );
  const seen = new Set<string>();
  const out: Nameable[] = [];
  for (const row of rows) {
    const name = row.vulnerability ?? "";
    if (name === "" || already.has(name) || seen.has(name)) continue;
    seen.add(name);
    out.push({ vulnerability: name, summary: row.summary ?? "", fixed: row.open === 0 });
  }
  return out;
}
