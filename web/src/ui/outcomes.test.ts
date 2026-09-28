// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { DISMISSING, dismisses, needsJustification } from "./outcomes";

describe("the outcomes that close a question", () => {
  // The server counts and filters by the outcomes that hide risk and carry no
  // date. A screen asking for a hand-written list leaves out whatever it grows.
  it("are the ones that hide risk and carry no date", () => {
    expect([...DISMISSING].sort()).toEqual(
      ["already-fixed", "mismatched", "not-applicable", "wont-fix"].sort(),
    );
  });

  it("leave out a promise, a deferral and an affected finding", () => {
    for (const each of ["affected", "deferred", "upgrade-needed", "patch-needed"]) {
      expect(dismisses(each)).toBe(false);
    }
  });
});

describe("the outcomes that state a reason", () => {
  it("are the two claims that something is not the problem here", () => {
    expect(needsJustification("not-applicable")).toBe(true);
    expect(needsJustification("mismatched")).toBe(true);
    expect(needsJustification("wont-fix")).toBe(false);
    expect(needsJustification(undefined)).toBe(false);
  });

  it("do not include a word naming a member every object inherits", () => {
    expect(needsJustification("constructor")).toBe(false);
    expect(dismisses("toString")).toBe(false);
  });
});
