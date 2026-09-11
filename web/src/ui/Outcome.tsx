// The outcomes. All but "affected" hide risk, which is the distinction that
// decides whether a second person has to agree — and the two that promise work
// hide it only until the date they promised, which is what they are gated on
// instead.
const said: Record<string, { label: string; color: string; means: string }> = {
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

// What an outcome is called in a sentence, for the places that say it in
// prose rather than as a chip. A word this does not know is shown as it
// arrived: a server that grows an outcome before the interface does should
// leave somebody reading something unfamiliar rather than a blank.
export function called(outcome?: string): string {
  return said[outcome ?? ""]?.label.toLowerCase() ?? outcome ?? "";
}

// The same word as a chip carries it, capitalised.
//
// Two screens kept partial copies of this map — the review queue knew four
// outcomes and the finding's claim card knew five, of seven — so a claim of
// "patch-needed" or "upgrade-needed" showed the stored token to the person
// being asked to agree with it. One map, and a word it does not know is still
// shown as it arrived.
export function labeled(outcome?: string): string {
  return said[outcome ?? ""]?.label ?? outcome ?? "";
}

export function Outcome({ outcome }: { outcome?: string }) {
  const it = said[outcome ?? ""];
  if (!it) return null;
  return (
    <span className="sev" title={it.means} style={{ "--c": it.color } as React.CSSProperties}>
      {it.label}
    </span>
  );
}

// The exchange format's own vocabulary, named as it is stored.
export type Justification =
  | "component_not_present"
  | "vulnerable_code_not_present"
  | "vulnerable_code_not_in_execute_path"
  | "vulnerable_code_cannot_be_controlled_by_adversary"
  | "inline_mitigations_already_exist";

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
export const JUSTIFICATIONS: { value: Justification; label: string; means: string }[] = [
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
];

const because = new Map(JUSTIFICATIONS.map((each) => [each.value as string, each]));

// Because renders a stored justification in words.
//
// One place, because two spellings of one vocabulary is how the list a person
// chooses from and the list they read back stop agreeing — which is how this
// started, with one screen labeling them and the other not.
export function Because({ code }: { code?: string | null }) {
  if (!code) return null;
  const it = because.get(code);
  if (!it) return <span className="mono">{code}</span>;
  return <span title={`${it.value} — ${it.means}`}>{it.label}</span>;
}
