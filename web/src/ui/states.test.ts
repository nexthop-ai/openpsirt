// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decidedAs } from "./decided";
import { drawn, said, STATES } from "./states";

describe("a decision state drawn on any screen", () => {
  // The findings list, the issue screen, a comparison and the register draw
  // the same fact about a group; one color per state, whichever draws it.
  it("draws each state in its own class", () => {
    expect(STATES.map(drawn)).toEqual(["open", "waiting", "agreed", "lapsed"]);
  });

  it("draws a group some occurrences answered and the rest did not as waiting", () => {
    expect(drawn(undefined)).toBe("waiting");
    expect(drawn("")).toBe("waiting");
  });

  it("names each state by the word a row shows, in the class a comparison draws", () => {
    expect(STATES.map((state) => decidedAs(state))).toEqual([
      { word: "Undecided", cls: "open" },
      { word: "Pending", cls: "waiting" },
      { word: "Decided", cls: "agreed" },
      { word: "Lapsed", cls: "lapsed" },
    ]);
    expect(decidedAs("")).toEqual({ word: "Partly", cls: "waiting" });
  });

  it("draws a decision sent back to its author as rejected, whatever its state", () => {
    expect(decidedAs("waiting", true)).toEqual({ word: "Rejected", cls: "lapsed" });
  });

  it("is drawn as open where the word is one nobody here knows", () => {
    expect(drawn("reconsidered")).toBe("open");
  });

  it("is said as it arrived where the word names a member every object inherits", () => {
    expect(said("constructor")).toBe("constructor");
    expect(drawn("toString")).toBe("open");
  });
});
