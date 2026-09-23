// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { Report } from "../api/intake";
import { dispositionSaid, needsReason, needsSecond, ready, rulable, standing } from "./inbox";

const report = (extra: Partial<Report>): Report =>
  ({ reference: "SONIC-R-2026-1", recorded_by: "them", recorded_at: "", ...extra }) as Report;

describe("a report's standing", () => {
  it("is open while nothing answers it", () => {
    expect(standing(report({}))).toEqual({ said: "Open", tone: "open" });
  });
  it("names a disposition waiting for a second person as waiting", () => {
    expect(standing(report({ ruling: 3, waiting: "rejected" }))).toEqual({
      said: "Rejected, waiting",
      tone: "waiting",
    });
  });
  it("names a disposition in force", () => {
    expect(standing(report({ ruling: 3, disposition: "duplicate" })).said).toBe("Duplicate");
  });
});

describe("which reports a ruling may cover", () => {
  it("is those nothing answers and no ruling holds", () => {
    expect(rulable(report({}))).toBe(true);
    expect(rulable(report({ ruling: 3, waiting: "rejected" }))).toBe(false);
    expect(rulable(report({ disposition: "accepted" }))).toBe(false);
  });
});

describe("the second person", () => {
  it("is asked for setting a claim aside and for nothing else", () => {
    expect(needsSecond("rejected")).toBe(true);
    expect(needsSecond("out-of-scope")).toBe(true);
    expect(needsSecond("duplicate")).toBe(false);
    expect(needsSecond("not-reproducible")).toBe(false);
  });
});

describe("a ruling ready to send", () => {
  it("needs a disposition", () => {
    expect(ready({ disposition: "", reasoning: "x", duplicateOf: "" })).toBe(false);
  });
  it("needs the issue a duplicate names, and no reason", () => {
    expect(needsReason("duplicate")).toBe(false);
    expect(ready({ disposition: "duplicate", reasoning: "", duplicateOf: "" })).toBe(false);
    expect(ready({ disposition: "duplicate", reasoning: "", duplicateOf: "CVE-1" })).toBe(true);
  });
  it("needs a reason for everything else", () => {
    expect(needsReason("rejected")).toBe(true);
    expect(needsReason("not-reproducible")).toBe(true);
    expect(ready({ disposition: "rejected", reasoning: "  ", duplicateOf: "" })).toBe(false);
    expect(ready({ disposition: "rejected", reasoning: "Slop.", duplicateOf: "" })).toBe(true);
  });
});

describe("a disposition's name", () => {
  it("is shown as it arrived where the table does not know it", () => {
    expect(dispositionSaid("out-of-scope")).toBe("Out of scope");
    expect(dispositionSaid("withdrawn-upstream")).toBe("withdrawn-upstream");
  });
});
