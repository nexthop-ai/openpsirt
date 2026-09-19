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

// BELOW_LOW is the two words a scanner reports that rank beneath every band
// and are still a rating: somebody looked and said it is not worth much. The
// server puts both in the low band — `rating.BandExpr` and `SeverityScore`
// both say so — so this says the same rather than a second thing.
export const BELOW_LOW = ["negligible", "none"] as const;

// bandOf is the band a rating is drawn in: one of the four, or "unrated".
//
// One answer, because there were four for the same row. A finding whose
// vulnerability carries no severity was counted as a medium by the chart, drawn
// as a low by the badge, given a low's stripe by the card, and given its own
// band by the tree strip — four answers about one nothing, on one screen.
//
// Rated negligible is not unrated. The two were folded together here and
// nowhere else: the server ranks both of the words below low inside the low
// band, and a reader was told nobody had looked at a finding somebody had
// looked at and dismissed.
export function bandOf(word: string | null | undefined): string {
  if (isBand(word ?? "")) return word as string;
  if ((BELOW_LOW as readonly string[]).includes(word ?? "")) return "low";
  return "unrated";
}

// ratedAs is the word a row says, which is what was rated rather than the band
// it falls in. They differ for exactly the two words below low: those draw in
// the low band, because that is where everything that sorts and filters puts
// them, and they say what somebody actually said.
export function ratedAs(word: string | null | undefined): string {
  const said = word ?? "";
  if (isBand(said) || (BELOW_LOW as readonly string[]).includes(said)) return said;
  return "unrated";
}
