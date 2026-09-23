// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { waitingFor, type Asked } from "./awaiting";

const blank: Asked = {
  outcome: "",
  needsJustification: false,
  justification: "",
  needsMitigation: false,
  mitigation: "",
  needsFixedVersion: false,
  fixedVersion: "",
  needsLanding: false,
  lands: "",
  needsDate: false,
  until: "",
  reasoning: "",
  covering: 12,
};

describe("what the decision form is waiting for", () => {
  it("asks for an outcome on a form nothing has been chosen on", () => {
    expect(waitingFor(blank)).toBe("Pick an outcome.");
  });

  // Down the form rather than in whatever order the conditions were written,
  // so somebody reading the line is sent to the next empty field.
  it("asks for the justification before the reasoning", () => {
    const said = waitingFor({
      ...blank,
      outcome: "not-applicable",
      needsJustification: true,
    });
    expect(said).toBe("Say which justification.");
  });

  it("asks for the date a deferral runs to", () => {
    const said = waitingFor({
      ...blank,
      outcome: "deferred",
      needsDate: true,
      reasoning: "Not reachable in this build.",
    });
    expect(said).toBe("A deferral needs a date.");
  });

  it("asks for the reasoning once the outcome is answered", () => {
    expect(waitingFor({ ...blank, outcome: "affected" })).toBe("Reasoning is required.");
  });

  // Every answer given and nothing to record: a form that would submit a claim
  // about no place at all.
  it("says so where every place has been excluded", () => {
    const said = waitingFor({
      ...blank,
      outcome: "affected",
      reasoning: "The service is exposed.",
      covering: 0,
    });
    expect(said).toBe("Every place is excluded, so there is nothing to decide.");
  });

  it("waits for nothing once every question asked has an answer", () => {
    const said = waitingFor({
      ...blank,
      outcome: "not-applicable",
      needsJustification: true,
      justification: "vulnerable_code_not_present",
      reasoning: "The module is not built into this image.",
    });
    expect(said).toBeNull();
  });
});
