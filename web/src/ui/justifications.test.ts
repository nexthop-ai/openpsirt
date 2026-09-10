import { describe, expect, it } from "vitest";
import { JUSTIFICATIONS, type Justification } from "./Outcome";

// The vocabulary was adopted so that export would be nearly free and CSAF is
// the adapter that matters, so whichever of these somebody picks is what ships
// to a customer, machine-readable, as our claim about their exposure. Offered
// as bare tokens it was a choice made off a list of five snake_case strings,
// which is an accuracy problem rather than a cosmetic one.
describe("the recognized justifications", () => {
  it("covers the whole vocabulary, so nothing falls back to its token", () => {
    // The list the screens draw from is the list the type allows. A value
    // added to one and not the other renders as a raw token on every screen,
    // which is the state this replaced.
    const offered = JUSTIFICATIONS.map((each) => each.value).sort();
    const known: Justification[] = [
      "component_not_present",
      "vulnerable_code_not_present",
      "vulnerable_code_not_in_execute_path",
      "vulnerable_code_cannot_be_controlled_by_adversary",
      "inline_mitigations_already_exist",
    ];
    expect(offered).toEqual([...known].sort());
  });

  it("says each one in words, and says what it claims", () => {
    for (const each of JUSTIFICATIONS) {
      expect(each.label, `${each.value} has no label`).not.toBe("");
      expect(each.means, `${each.value} says nothing about what it claims`).not.toBe("");
      // The label is the point: a token repeated as its own label is the
      // defect wearing a different field name.
      expect(each.label, `${each.value} is labeled with its own token`).not.toBe(each.value);
      expect(each.label).not.toContain("_");
    }
  });

  it("gives each one a distinct label", () => {
    // Two claims reading alike is worse than a token, because a token at least
    // tells them apart.
    const labels = new Set(JUSTIFICATIONS.map((each) => each.label));
    expect(labels.size).toBe(JUSTIFICATIONS.length);
  });
});
