import { describe, expect, it } from "vitest";

import { here, ruleIn, type Kept } from "./Saved";

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

  it("is none of them on a list nobody kept", () => {
    expect(ruleIn(kept, new URLSearchParams("component=openssl"))).toBeUndefined();
  });
});
