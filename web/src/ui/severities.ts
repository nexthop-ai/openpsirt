// The severity ladder, in one place.
//
// It was written out five times in the interface and three more in the server,
// under seven names and with three different memberships — four words in some,
// six in others, and one list with "everything" on the front for the triage
// floor. Three copies of an ordering is three chances for a word added to one
// to be missing from the others, which reads as a rating that sorts one way
// and filters another.

// BANDS is the four rated words, worst first: the order a report reads in and
// the order somebody looks for.
export const BANDS = ["critical", "high", "medium", "low"] as const;

// ROLLED is what a count over a set of findings comes back as: the four, plus
// the one word everything nobody rated folds into. The server rolls a
// subtree's or a component's issues up through the list that says which words
// are real, so "unrated" is a band on the wire and has to be one here — a
// screen drawing only the four shows a split that does not sum to the count
// printed beside it, which is the one thing a split must do.
export const ROLLED = [...BANDS, "unrated"] as const;

// FLOORS is the same four least-first, which is how a threshold is offered —
// a floor is picked by asking "at least this bad", and a list running downward
// asks it backwards.
export const FLOORS = ["low", "medium", "high", "critical"] as const;

// RECORDABLE is every word somebody may type when they record a flaw by hand.
// Wider than the bands by the two a scanner reports and nobody ranks:
// "negligible" and "none" are answers, and they rank below every band, so
// they survive no floor at all.
export const RECORDABLE = [...BANDS, "negligible", "none"] as const;

// THE_LINE is what a triage floor may be set to: the four, least first, with
// "everything" in front for the deployment that keeps all of it. The word is
// not a severity — it is the absence of a floor — which is why it lives here
// rather than in the ladder above.
export const THE_LINE = ["everything", ...FLOORS] as const;

export type Band = (typeof BANDS)[number];

// COLORS is the token each band is drawn in.
//
// Written out rather than composed from the word. A name built at run time is
// one no check can follow — the token gate reads `var(--name)` literally, and
// `var(--sev-${band})` is a reference it cannot put to the set of definitions,
// so a renamed token would be dropped by CSS in silence.
//
// Keyed on Band, so a rung added above with no color here does not compile.
// That is a stronger guarantee than the gate: it is the compiler rather than a
// script somebody has to run.
export const COLORS: Record<Band, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};

// isBand reports whether a word is one of the four, which is what decides
// whether it gets a color of its own.
export function isBand(word: string): word is Band {
  return (BANDS as readonly string[]).includes(word);
}

// bandOf is the word a rating is drawn with: one of the four, or "unrated".
//
// One answer, because there were four for the same row. A finding whose
// vulnerability carries no severity was counted as a medium by the chart, drawn
// as a low by the badge, given a low's stripe by the card, and given its own
// band by the tree strip — four answers about one nothing, on one screen.
export function bandOf(word: string | null | undefined): string {
  return isBand(word ?? "") ? (word as string) : "unrated";
}
