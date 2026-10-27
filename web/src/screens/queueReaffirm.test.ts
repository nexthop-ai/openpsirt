// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { reaffirmedNotice, whyLapsed } from "./QueueReaffirm";

describe("reaffirmedNotice", () => {
  it("says nothing waits where every decision stood", () => {
    expect(reaffirmedNotice({ decisions: 3, waiting: 0 })).toBe("Reaffirmed 3 decisions.");
  });
  it("counts the decisions waiting for a second person", () => {
    expect(reaffirmedNotice({ decisions: 1, waiting: 1 })).toBe(
      "Reaffirmed 1 decision; 1 waits for a second person.",
    );
  });
});

describe("whyLapsed", () => {
  it("names a version move", () => {
    expect(whyLapsed({ code_moved: true, rated_worse: false })).toEqual(["Code moved"]);
  });
  it("names the band a rise went between", () => {
    expect(whyLapsed({ code_moved: false, rated_worse: true, was: "medium", now: "high" })).toEqual(
      ["Rated worse: medium → high"],
    );
  });
  it("calls a decision made about an unrated issue unrated", () => {
    expect(whyLapsed({ code_moved: false, rated_worse: true, now: "critical" })).toEqual([
      "Rated worse: unrated → critical",
    ]);
  });
  it("names both where both hold", () => {
    expect(
      whyLapsed({ code_moved: true, rated_worse: true, was: "low", now: "high" }),
    ).toHaveLength(2);
  });
});
