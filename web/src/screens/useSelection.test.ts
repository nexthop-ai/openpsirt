// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { questionIn, untaken } from "./useSelection";
import type { Row } from "./list";

// The definition of a change of question decides when the selection is emptied,
// and the selection is what a bulk act writes against. Both directions matter:
// too narrow and rows chosen under one question are written under another; too
// wide and turning the page throws away what somebody ticked.
describe("what the list is asking", () => {
  it("is the same question from a different row", () => {
    // The selection is deliberately wider than a page — the bar says "across
    // pages" — so paging must not empty it.
    expect(questionIn(new URLSearchParams("state=undecided&offset=50"))).toBe(
      questionIn(new URLSearchParams("state=undecided")),
    );
    expect(questionIn(new URLSearchParams("state=undecided&offset=50"))).toBe(
      questionIn(new URLSearchParams("state=undecided&offset=200")),
    );
  });

  it("is a different question when a filter moves", () => {
    // A triager filtering to low, ticking thirty and then clicking critical
    // had a bar still saying thirty while four rows were listed — and handing
    // them over wrote assignments for twenty-six rows nobody could see.
    expect(questionIn(new URLSearchParams("floor=low"))).not.toBe(
      questionIn(new URLSearchParams("floor=critical")),
    );
    expect(questionIn(new URLSearchParams(""))).not.toBe(
      questionIn(new URLSearchParams("state=undecided")),
    );
  });

  it("is a different question when a filter is added or removed", () => {
    expect(questionIn(new URLSearchParams("state=undecided&offset=50"))).not.toBe(
      questionIn(new URLSearchParams("state=undecided&only=exploited&offset=50")),
    );
  });

  it("leaves the page size in the question", () => {
    // Changing how many rows a page holds re-cuts the population the selection
    // was made out of, unlike moving through it.
    expect(questionIn(new URLSearchParams("limit=50"))).not.toBe(
      questionIn(new URLSearchParams("limit=200")),
    );
  });
});

describe("what an act did not take", () => {
  const row = (vulnerability: string, fold: string) => ({ vulnerability, fold }) as Row;
  const picked = new Map<string, Row>([
    ["a", row("CVE-1", "curl@8")],
    ["b", row("CVE-2", "curl@8")],
    ["c", row("CVE-1", "openssl@3")],
  ]);
  it("keeps the rows the server names as left, by issue and fold", () => {
    expect(untaken(picked, [{ vulnerability: "CVE-1", fold: "curl@8" }]).map(([k]) => k)).toEqual([
      "a",
    ]);
  });
  it("keeps nothing when everything moved", () => {
    expect(untaken(picked, [])).toEqual([]);
  });
});
