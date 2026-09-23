// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { JUSTIFICATIONS, JUSTIFICATIONS_CORRECTING, type Justification } from "./Outcome";

// The vocabulary was adopted so that export would be nearly free and CSAF is
// the adapter that matters, so whichever of these somebody picks is what ships
// to a customer, machine-readable, as our claim about their exposure. Offered
// as bare tokens it was a choice made off a list of five snake_case strings,
// which is an accuracy problem rather than a cosmetic one.
describe("the recognized justifications", () => {
  it("names the whole vocabulary the exchange format defines", () => {
    // The type is read out of this list, so a value in one and not the other
    // is a compile error rather than something to assert. What is left worth
    // checking is the list against the format: these five are what CSAF
    // defines, and a sixth here would ship a token no consumer recognizes.
    expect(JUSTIFICATIONS.map((each) => each.value as Justification).sort()).toEqual([
      "component_not_present",
      "inline_mitigations_already_exist",
      "vulnerable_code_cannot_be_controlled_by_adversary",
      "vulnerable_code_not_in_execute_path",
      "vulnerable_code_not_present",
    ]);
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

  it("offers a correction only the reasons no version bump can answer", () => {
    // A correction stands at every version, so a reason a bump can address
    // would be a judgment about risk that nothing re-examines. The endpoint
    // refuses the other three; offering them here would be a refusal somebody
    // meets after writing the reasoning.
    expect(JUSTIFICATIONS_CORRECTING.map((each) => each.value).sort()).toEqual([
      "component_not_present",
      "vulnerable_code_not_present",
    ]);
  });

  it("gives each one a distinct label", () => {
    // Two claims reading alike is worse than a token, because a token at least
    // tells them apart.
    const labels = new Set(JUSTIFICATIONS.map((each) => each.label));
    expect(labels.size).toBe(JUSTIFICATIONS.length);
  });
});
