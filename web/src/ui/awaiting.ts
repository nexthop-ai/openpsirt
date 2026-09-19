// The answers the decision form is still waiting for.
//
// Nothing is chosen for anybody, so an empty form is the ordinary state and
// the button is refused until each question being asked has an answer. A form
// that does not say which question leaves the control dead, the shortcut it
// advertises doing nothing when pressed, and no way to find out what is
// missing but to guess.
//
// One rule rather than two: the sentence is what the form says, and having a
// sentence is what makes it not ready. Refusals inside the submit path,
// behind a button disabled whenever any of them would fire, can never be
// read.

export type Asked = {
  outcome: string;
  // Each of these is asked only for some outcomes, which is why the questions
  // are answered here rather than counted.
  needsJustification: boolean;
  justification: string;
  needsMitigation: boolean;
  mitigation: string;
  needsFixedVersion: boolean;
  fixedVersion: string;
  needsLanding: boolean;
  lands: string;
  needsDate: boolean;
  until: string;
  reasoning: string;
  // The places the claim would cover. Excluding every one of them leaves
  // a form with every answer and nothing to record.
  covering: number;
};

// In the order the form asks, so somebody reading it is sent to the next empty
// field rather than to whichever question was checked first.
export function waitingFor(asked: Asked): string | null {
  if (asked.outcome === "") return "Pick an outcome.";
  if (asked.needsJustification && asked.justification === "") return "Say which justification.";
  if (asked.needsMitigation && asked.mitigation.trim() === "") return "Say what stops it.";
  if (asked.needsFixedVersion && asked.fixedVersion.trim() === "") {
    return "Say which package version the fix arrived in, so somebody can check it.";
  }
  if (asked.needsLanding && asked.lands === "") return "A backport needs the date it lands.";
  if (asked.needsDate && asked.until === "") return "A deferral needs a date.";
  if (asked.reasoning.trim() === "") return "Reasoning is required.";
  if (asked.covering === 0) return "Every place is excluded, so there is nothing to decide.";
  return null;
}
