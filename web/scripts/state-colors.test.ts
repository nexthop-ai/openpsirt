// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { doneButTrouble, sweep } from "./state-colors.mjs";

describe("a state chip's color", () => {
  it("reports a failure drawn as done", () => {
    expect(
      doneButTrouble("x.tsx", `<span className="state closed" title={why}>failing</span>`),
    ).toEqual(["x.tsx:1: failing"]);
  });

  it("passes a done chip that says it is done", () => {
    expect(doneButTrouble("x.tsx", `<span className="state closed">scanned</span>`)).toEqual([]);
  });

  it("passes a failure drawn as bad", () => {
    expect(doneButTrouble("x.tsx", `<span className="state bad">stopped</span>`)).toEqual([]);
  });

  it("finds no failure drawn as done on any screen", () => {
    const { files, found } = sweep();
    expect(files, "no screens were found, so this checked nothing").toBeGreaterThan(0);
    expect(found).toEqual([]);
  });
});
