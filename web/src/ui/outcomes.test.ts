// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { classesOf } from "./outcomes";
import { PUBLISHED } from "../test/outcomes";

describe("the outcomes that close a question", () => {
  // The server counts and filters by the outcomes that hide risk and carry no
  // date. A screen asking for a hand-written list leaves out whatever it grows.
  it("are the ones published as hiding risk and carrying no date", () => {
    expect([...classesOf(PUBLISHED).dismissing].sort()).toEqual(
      ["already-fixed", "mismatched", "not-applicable", "wont-fix"].sort(),
    );
  });

  it("leave out a promise, a deferral and an affected finding", () => {
    const { dismisses } = classesOf(PUBLISHED);
    for (const each of ["affected", "deferred", "upgrade-needed", "patch-needed"]) {
      expect(dismisses(each)).toBe(false);
    }
  });

  it("follow an outcome the server moves to another class", () => {
    // A deferral published without its date is a dismissal here too.
    const moved = PUBLISHED.map((each) =>
      each.outcome === "deferred" ? { ...each, dated: false } : each,
    );
    expect(classesOf(moved).dismisses("deferred")).toBe(true);
  });
});

describe("the outcomes that state a reason", () => {
  it("are the ones the server says state one", () => {
    const { needsJustification } = classesOf(PUBLISHED);
    expect(needsJustification("not-applicable")).toBe(true);
    expect(needsJustification("mismatched")).toBe(true);
    expect(needsJustification("wont-fix")).toBe(false);
    expect(needsJustification(undefined)).toBe(false);
  });

  it("do not include a word naming a member every object inherits", () => {
    const classes = classesOf(PUBLISHED);
    expect(classes.needsJustification("constructor")).toBe(false);
    expect(classes.dismisses("toString")).toBe(false);
  });
});

describe("before the server has answered", () => {
  it("puts nothing in any class and says it does not know", () => {
    const classes = classesOf(undefined);
    expect(classes.known).toBe(false);
    expect(classes.dismissing).toEqual([]);
    expect(classes.hidesRisk("deferred")).toBe(false);
  });
});
