// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { stateOf } from "./FindingClaim";
import { labeled } from "../ui/Outcome";

// The state a finding's header says it is in. Each case reaches one arm.
type Claims = Parameters<typeof stateOf>[0];
// Every claim here is a dismissal, which needs a second person.
const claims = (...states: string[]): Claims =>
  states.map((state) => ({
    decision: { state, outcome: "wont-fix", needs_approval: true },
  })) as unknown as Claims;

describe("the state a finding is said to be in", () => {
  it("is decided where no claim stands and every place is answered", () => {
    expect(stateOf([], 3, 3, [])).toEqual({ label: "Decided", cls: "agreed" });
  });

  it("is undecided where no claim stands and nothing is answered", () => {
    expect(stateOf([], 0, 3, [])).toEqual({ label: "Undecided", cls: "open" });
    expect(stateOf([], 2, 0, [])).toEqual({ label: "Undecided", cls: "open" });
  });

  it("is pending where any claim waits for a second person", () => {
    expect(stateOf(claims("approved", "proposed", "lapsed"), 1, 3, []).label).toBe(
      "Pending approval",
    );
  });

  it("is in force where a proposed claim needs nobody", () => {
    const affected = [
      { decision: { state: "proposed", outcome: "affected" } },
    ] as unknown as Claims;
    expect(stateOf(affected, 1, 1, [])).toEqual({
      label: `${labeled("affected")} · in force`,
      cls: "agreed",
    });
  });

  it("names the outcome where every claim is approved", () => {
    expect(stateOf(claims("approved", "approved"), 2, 2, [])).toEqual({
      label: `${labeled("wont-fix")} · approved`,
      cls: "agreed",
    });
  });

  it("is lapsed where a claim lapsed and none waits", () => {
    expect(stateOf(claims("approved", "lapsed"), 2, 2, [])).toEqual({
      label: "Lapsed",
      cls: "lapsed",
    });
  });

  it("is decided where claims stand in no state the others name", () => {
    expect(stateOf(claims("approved", "withdrawn"), 2, 2, [])).toEqual({
      label: "Decided",
      cls: "agreed",
    });
  });

  it("reads the overall states where there is one per claim, and the claims' own otherwise", () => {
    expect(stateOf(claims("approved"), 1, 1, ["proposed"]).label).toBe("Pending approval");
    expect(stateOf(claims("proposed"), 1, 1, ["approved", "approved"]).label).toBe(
      "Pending approval",
    );
  });
});
