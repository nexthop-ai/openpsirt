// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Outcome as Word } from "./outcomes";

// The outcomes. All but "affected" hide risk, which is the distinction that
// decides whether a second person has to agree — and the two that promise work
// hide it only until the date they promised, which is what they are gated on
// instead. Keyed by every outcome the server records, so one it adds is a
// compile error here until it has a label.
const said: Record<Word, { label: string; color: string; means: string }> = {
  affected: {
    label: "Affected",
    color: "var(--sev-high)",
    means: "this applies to us and needs fixing",
  },
  "not-applicable": {
    label: "Not applicable",
    color: "var(--ok)",
    means: "this does not affect us, for one of the recognized reasons",
  },
  mismatched: {
    label: "Wrong match",
    color: "var(--ok)",
    means:
      "the scanner matched this against something that is not here, and no version bump makes that right",
  },
  deferred: {
    label: "Deferred",
    color: "var(--wait)",
    means: "it applies, and is being put off until a date",
  },
  "wont-fix": {
    label: "Will not fix",
    color: "var(--sev-critical)",
    means: "it applies and will not be fixed",
  },
  "upgrade-needed": {
    label: "Upgrade planned",
    color: "var(--wait)",
    means: "the package is being moved to a newer version by a date",
  },
  "patch-needed": {
    label: "Backport planned",
    color: "var(--wait)",
    means: "a fix is being carried in by a date, and the version does not move",
  },
  "already-fixed": {
    label: "Already fixed",
    color: "var(--ok)",
    means: "the fix is already in the version shipping here",
  },
};

// Every outcome the interface knows, in the order above, for a control that
// offers them.
export function outcomeWords(): string[] {
  return Object.keys(said);
}

// An outcome's name in a sentence, for the places that say it in
// prose rather than as a chip. A word this does not know is shown as it
// arrived: a server that grows an outcome before the interface does should
// leave somebody reading something unfamiliar rather than a blank.
export function called(outcome?: string): string {
  return of(outcome)?.label.toLowerCase() ?? outcome ?? "";
}

// This map's entry for a word, or nothing.
//
// Asked through a guard rather than by indexing, because an object literal
// inherits from the prototype: a server-supplied word that names a member of
// it — `constructor`, `toString` — is a function, and the `?.` that guards the
// lookup does not guard the field read after it.
function of(outcome?: string): (typeof said)[Word] | undefined {
  const word = outcome ?? "";
  return Object.hasOwn(said, word) ? said[word as Word] : undefined;
}

// The same word as a chip carries it, capitalized.
//
// Every screen labels an outcome from this one map, so a partial copy cannot
// show a stored token to the person asked to agree with it. A word it does not
// know is shown as it arrived.
export function labeled(outcome?: string): string {
  return of(outcome)?.label ?? outcome ?? "";
}

// The same word as a chip, with its color and its meaning.
//
// A word this does not know is shown as it arrived, the way the two renderers
// above do it. In the tables that draw it the outcome is the whole of the
// cell, so an empty one reads as a judgment nobody made.
export function Outcome({ outcome }: { outcome?: string }) {
  if (!outcome) return null;
  const it = of(outcome);
  if (!it) return <span className="hint">{outcome}</span>;
  return (
    <span className="sev" title={it.means} style={{ "--c": it.color } as React.CSSProperties}>
      {it.label}
    </span>
  );
}

// Each one said in words, with a line saying what it claims.
//
// The vocabulary was adopted so that export would be nearly free, and CSAF is
// the adapter that matters — so whichever of these somebody picks is what
// ships to a customer, machine-readable, as our claim about their exposure.
// Offered as bare tokens, that choice is made at the end of a long day off a
// list of five snake_case strings, which is an accuracy problem rather than a
// cosmetic one.
//
// The stored token is still what an approver checks, so it stays reachable:
// the visible text is the label, and the title carries the token beside the
// meaning.
export const JUSTIFICATIONS = [
  {
    value: "component_not_present",
    label: "The component is not here",
    means: "what the advisory names is not in this build at all",
  },
  {
    value: "vulnerable_code_not_present",
    label: "The vulnerable code is not here",
    means: "the component ships, but the code the flaw is in was not built into it",
  },
  {
    value: "vulnerable_code_not_in_execute_path",
    label: "The vulnerable code never runs",
    means: "the code ships, and nothing in this product can reach it",
  },
  {
    value: "vulnerable_code_cannot_be_controlled_by_adversary",
    label: "An attacker cannot reach it",
    means: "the code runs, and nothing an attacker controls gets to it",
  },
  {
    value: "inline_mitigations_already_exist",
    label: "Something already stops it",
    means: "a control elsewhere in the product prevents it, and saying which is required",
  },
] as const;

// The reasons an outcome may state, and what is left of a choice when the
// outcome moves under it.
//
// A form that narrows the list and keeps the old value sends a reason the
// endpoint refuses, and a select whose value matches no option draws blank —
// so nobody sees what is about to be sent. Dropped rather than replaced: which
// reason applies is a claim a reader takes literally, and a form that picks
// one when the last became unavailable has answered for somebody.
export function reasonsFor(outcome?: string) {
  return outcome === "mismatched" ? JUSTIFICATIONS_CORRECTING : JUSTIFICATIONS;
}

export function reasonOffered(outcome: string | undefined, chosen: string): string {
  return reasonsFor(outcome).some((each) => each.value === chosen) ? chosen : "";
}

// The reasons a correction may state: the two that say something is not there.
//
// Derived rather than written out again. The other three describe how code is
// reached or what already stops it, and a version bump changes both — a
// correction carries past every bump, so one of those recorded as a correction
// would put a judgment about risk beyond the rule that re-examines it. The
// endpoint refuses them; offering them here would be a refusal somebody meets
// after writing the reasoning.
export const JUSTIFICATIONS_CORRECTING = JUSTIFICATIONS.filter(
  (each) => each.value === "component_not_present" || each.value === "vulnerable_code_not_present",
);

// The exchange format's own vocabulary, named as it is stored.
//
// Derived from the list rather than written beside it, which makes a
// divergence between the two unrepresentable: the compiler enforces it.
export type Justification = (typeof JUSTIFICATIONS)[number]["value"];

const because = new Map(JUSTIFICATIONS.map((each) => [each.value as string, each]));

// Because renders a stored justification in words.
//
// One place, because two spellings of one vocabulary is how the list a person
// chooses from and the list they read back stop agreeing.
export function Because({ code }: { code?: string | null }) {
  if (!code) return null;
  const it = because.get(code);
  if (!it) return <span className="mono">{code}</span>;
  return <span title={`${it.value} — ${it.means}`}>{it.label}</span>;
}
