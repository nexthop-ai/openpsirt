// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import scope from "../../../testdata/scope-words.json";
import { here, ruleIn, SCOPE, type Kept } from "./Saved";

// The saved filter a list is narrowed by.
//
// The answer decides two things: which name the dropdown shows as open, and —
// where that one prepares a claim — which findings open with a decision form
// filled in. It is read off the address rather than remembered from the act of
// picking, because a rule that outlived the narrowing it was picked for would
// fill a form on a finding it never drew, with somebody's name about to go on
// the claim.

const kept: Kept[] = [
  { name: "overdue kernel", query: "component=linux&state=undecided" },
  {
    name: "put off drivers",
    query: "component=firmware",
    prepares: { outcome: "deferred", reasoning: "Next quarter.", defer_days: 90 },
  },
];

describe("the filter a list is narrowed by", () => {
  it("is the one whose address the list is at", () => {
    const at = new URLSearchParams("component=firmware");
    expect(ruleIn(kept, at)?.name).toBe("put off drivers");
  });

  it("is none of them once the list narrows further", () => {
    // The question changed, so what a rule prepared about the old one no
    // longer applies to what is on screen.
    const at = new URLSearchParams("component=firmware&severity=critical");
    expect(ruleIn(kept, at)).toBeUndefined();
  });

  it("survives paging, which is a position rather than a narrowing", () => {
    const at = new URLSearchParams("component=firmware&offset=50");
    expect(ruleIn(kept, at)?.name).toBe("put off drivers");
    expect(here(at)).toBe("component=firmware");
  });

  it("is the same one in any scope, which a saved filter does not keep", () => {
    const at = new URLSearchParams("stream=main&component=firmware&variant=x86&beneath=zlib");
    expect(ruleIn(kept, at)?.name).toBe("put off drivers");
    expect(here(at)).toBe("component=firmware");
  });

  it("is the same one in any grouping, which a saved filter does not keep", () => {
    const at = new URLSearchParams("view=components&component=firmware");
    expect(ruleIn(kept, at)?.name).toBe("put off drivers");
  });

  it("is never one that keeps nothing, which would read as open on every bare list", () => {
    const emptied: Kept[] = [
      {
        name: "all of main",
        query: "",
        prepares: { outcome: "wont-fix", reasoning: "Everything." },
      },
    ];
    expect(ruleIn(emptied, new URLSearchParams("stream=main"))).toBeUndefined();
    expect(ruleIn(emptied, new URLSearchParams())).toBeUndefined();
  });

  it("is none of them on a list nobody kept", () => {
    expect(ruleIn(kept, new URLSearchParams("component=openssl"))).toBeUndefined();
  });
});

// The server drops the same words before it stores a filter, and its own test
// compares its list with the same file, so a word dropped on one side and kept
// on the other fails on the side that was not changed.
describe("the scope a kept filter leaves out", () => {
  it("is the server's", () => {
    expect(scope.words.length).toBeGreaterThan(0);
    expect(SCOPE).toEqual(scope.words);
  });

  it("is dropped from the address a kept query is compared with", () => {
    const params = new URLSearchParams(scope.words.map((word) => [word, "x"]));
    params.append("exploited", "1");
    expect(here(params)).toBe("exploited=1");
  });
});
