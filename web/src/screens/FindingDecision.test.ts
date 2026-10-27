// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { stateOf } from "./FindingDecision";
import { labeled } from "../ui/Outcome";

// The state a finding's header says it is in. Each case reaches one arm.
type Decisions = Parameters<typeof stateOf>[0];
// Every decision here is a dismissal, which needs a second person.
const decisions = (...states: string[]): Decisions =>
  states.map((state) => ({
    decision_occurrence: { state, outcome: "wont-fix", needs_approval: true },
  })) as unknown as Decisions;

describe("the state a finding is said to be in", () => {
  it("is decided where no decision stands and every occurrence is answered", () => {
    expect(stateOf([], 3, 3, [])).toEqual({ label: "Decided", cls: "agreed" });
  });

  it("is undecided where no decision stands and nothing is answered", () => {
    expect(stateOf([], 0, 3, [])).toEqual({ label: "Undecided", cls: "open" });
    expect(stateOf([], 2, 0, [])).toEqual({ label: "Undecided", cls: "open" });
  });

  it("is pending where any decision waits for a second person", () => {
    expect(stateOf(decisions("approved", "proposed", "lapsed"), 1, 3, []).label).toBe(
      "Pending approval",
    );
  });

  it("is pending where its one decision is proposed and waits for a second person", () => {
    expect(stateOf(decisions("proposed"), 1, 1, [])).toEqual({
      label: "Pending approval",
      cls: "waiting",
    });
  });

  it("is in force where a proposed decision needs nobody", () => {
    const affected = [
      { decision_occurrence: { state: "proposed", outcome: "affected" } },
    ] as unknown as Decisions;
    expect(stateOf(affected, 1, 1, [])).toEqual({
      label: `${labeled("affected")} · in force`,
      cls: "agreed",
    });
  });

  it("names the outcome where every decision is approved", () => {
    expect(stateOf(decisions("approved", "approved"), 2, 2, [])).toEqual({
      label: `${labeled("wont-fix")} · approved`,
      cls: "agreed",
    });
  });

  it("is lapsed where a decision lapsed and none waits", () => {
    expect(stateOf(decisions("approved", "lapsed"), 2, 2, [])).toEqual({
      label: "Lapsed",
      cls: "lapsed",
    });
  });

  it("is decided where decisions stand in no state the others name", () => {
    expect(stateOf(decisions("approved", "withdrawn"), 2, 2, [])).toEqual({
      label: "Decided",
      cls: "agreed",
    });
  });

  it("reads the overall states where there is one per decision, and the decisions' own otherwise", () => {
    expect(stateOf(decisions("approved"), 1, 1, ["proposed"]).label).toBe("Pending approval");
    expect(stateOf(decisions("proposed"), 1, 1, ["approved", "approved"]).label).toBe(
      "Pending approval",
    );
  });
});
