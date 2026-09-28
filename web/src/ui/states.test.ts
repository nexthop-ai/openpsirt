// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decidedAs } from "./decided";
import { drawn, said, STATES } from "./states";

describe("a decision state drawn on any screen", () => {
  // The findings list, the issue screen, a comparison and the register draw
  // the same fact about a group; one color per state, whichever draws it.
  it("takes the same class on the lists as on a comparison", () => {
    for (const state of STATES) expect(decidedAs(state).cls).toBe(drawn(state));
  });

  it("takes the same class for a group some places answered and the rest did not", () => {
    expect(drawn(undefined)).toBe(decidedAs(undefined).cls);
    expect(drawn("")).toBe(decidedAs("").cls);
  });

  it("is drawn as open where the word is one nobody here knows", () => {
    expect(drawn("reconsidered")).toBe("open");
  });

  it("is said as it arrived where the word names a member every object inherits", () => {
    expect(said("constructor")).toBe("constructor");
    expect(drawn("toString")).toBe("open");
  });
});
