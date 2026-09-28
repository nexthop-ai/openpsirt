// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { laddersIn, listsIn, groupsIn } from "./one-ladder.mjs";

// This gate refuses a second copy of the severity ladder. It is wired as
// `npm run ladder` and its only consumer is an exit code, which cannot tell a
// check that found nothing from one that looked at nothing.
//
// Both directions per shape — one input that must be reported and one that
// must not — because the failure that matters here is the check going quiet.

// What the program reports, which is what laddersIn returns and nothing more.
const found = (source: string) => laddersIn(source).map((each: { rungs: string[] }) => each.rungs);

describe("the shapes a ladder is written in", () => {
  it("reads a plain list of the words", () => {
    expect(found(`const x = ["critical", "high", "medium", "low"];`)).toEqual([
      ["critical", "high", "medium", "low"],
    ]);
  });

  it("reads an array of objects, which is the shape that draws bands", () => {
    // Four bands beside a count of five leave a quarter of what is under a
    // node invisible.
    expect(
      found(`const BANDS = [
        { key: "critical", color: "var(--sev-critical)" },
        { key: "high", color: "var(--sev-high)" },
        { key: "medium", color: "var(--sev-medium)" },
        { key: "low", color: "var(--sev-low)" },
      ];`),
    ).toEqual([["critical", "high", "medium", "low"]]);
  });

  it("reads an array of tuples", () => {
    expect(
      found(`const bands: [string, number][] = [
        ["critical", changed?.critical ?? 0],
        ["high", changed?.high ?? 0],
        ["medium", changed?.medium ?? 0],
        ["low", changed?.low ?? 0],
      ];`),
    ).toEqual([["critical", "high", "medium", "low"]]);
  });

  it("reads a tuple list of floors, least first", () => {
    expect(
      found(`const SEVERITIES = [
        ["low", "Any"],
        ["medium", "Medium and above"],
        ["high", "High and above"],
        ["critical", "Critical only"],
      ] as const;`),
    ).toEqual([["low", "medium", "high", "critical"]]);
  });
});

describe("what is not a ladder", () => {
  it("leaves a list that shares two words with one", () => {
    // Fix states hold "none" and "unknown", which are rungs and are not
    // severities here. A pair of shared words is a coincidence; a list that is
    // mostly rungs is the ladder.
    expect(
      found(`const FIX_STATES = [
        ["", "Any"],
        ["fixed", "Fixed upstream"],
        ["none", "No fix released"],
        ["wont-fix", "Will not fix"],
        ["unknown", "Not stated"],
        ["mixed", "Differs between builds"],
      ] as const;`),
    ).toEqual([]);
  });

  it("leaves a label that happens to read like a rung", () => {
    // CVSS metric values. Three of the labels are rungs and none of them is a
    // severity, so the word has to be the entry's own name rather than what is
    // printed beside it.
    expect(
      found(`const values = [
        { value: "H", label: "High" },
        { value: "L", label: "Low" },
        { value: "N", label: "None" },
      ];`),
    ).toEqual([]);
  });

  it("leaves one rung used as a word", () => {
    expect(found(`const x = ["critical", "banana"];`)).toEqual([]);
    // Alone it is a majority of its list, and still one word.
    expect(found(`const x = ["critical"];`)).toEqual([]);
  });

  it("leaves a switch, which is a mapping with every arm visible", () => {
    expect(
      found(`switch (band) {
        case "critical": return 4;
        case "high": return 3;
      }`),
    ).toEqual([]);
  });
});

describe("a ladder of any length", () => {
  it("reads an array of objects however long each entry runs", () => {
    const hint = "x".repeat(90);
    const entries = [
      "critical",
      "high",
      "medium",
      "low",
      "unrated",
      "unknown",
      "negligible",
      "none",
    ]
      .map(
        (key) =>
          `  { key: "${key}", label: "${key}", color: "var(--sev-${key})", hint: "${hint}" },`,
      )
      .join("\n");
    const source = `const BANDS = [\n${entries}\n];`;
    expect(source.length).toBeGreaterThan(800);
    expect(found(source)).toEqual([
      ["critical", "high", "medium", "low", "unrated", "unknown", "negligible", "none"],
    ]);
  });

  it("is not closed by a bracket inside a string or a comment", () => {
    expect(
      found(`const BANDS = [
        { key: "critical", label: "a ] b" }, // not the end ]
        { key: "high", label: "c } d" },
        { key: "medium" },
      ];`),
    ).toEqual([["critical", "high", "medium"]]);
  });
});

describe("text the bracket matcher cannot read", () => {
  it("skips an escaped quote inside a string", () => {
    expect(
      found(`const BANDS = [
        { key: "critical", hint: "a 5\\" gap" },
        { key: "high", hint: 'it\\'s' },
        { key: "medium" },
      ];`),
    ).toEqual([["critical", "high", "medium"]]);
  });

  it("reads past an apostrophe in JSX text", () => {
    expect(
      found(`const BANDS = [
        { key: "critical", note: <p>it's bad</p> },
        { key: "high" },
        { key: "medium" },
      ];`),
    ).toEqual([["critical", "high", "medium"]]);
  });

  it("reads past an escaped bracket in a regular expression", () => {
    expect(
      found(`const BANDS = [
        { key: "critical", test: /\\]/ },
        { key: "high" },
        { key: "medium" },
      ];`),
    ).toEqual([["critical", "high", "medium"]]);
  });

  it("reads a block it cannot close over a window", () => {
    expect(
      found(`const BANDS = [
        { key: "critical", test: /[(]/ },
        { key: "high" },
        { key: "medium" },
      ];`),
    ).toEqual([["critical", "high", "medium"]]);
  });

  it("reads a ladder nested among other entries", () => {
    expect(
      found(`const FIELDS = [
        { name: "product" },
        { name: "stream" },
        { name: "variant" },
        { name: "severity", options: [
            ["critical", "C"],
            ["high", "H"],
        ] },
      ];`),
    ).toEqual([["critical", "high"]]);
  });
});

describe("one report per copy", () => {
  it("reports a line once, however many shapes match on it", () => {
    expect(found(`const x = [["critical", "high"], ["medium", "low"]];`)).toHaveLength(1);
  });
});

describe("the two readers underneath", () => {
  it("listsIn takes only bare string literals", () => {
    expect(listsIn(`["a", "b"]`)).toHaveLength(1);
    expect(listsIn(`[{ key: "a" }, { key: "b" }]`)).toHaveLength(0);
  });

  it("groupsIn takes only what names an entry", () => {
    expect(groupsIn(`[{ key: "a" }, { key: "b" }]`)[0].words).toEqual(["a", "b"]);
    // Nothing naming an entry is nothing to report, so the block is dropped
    // rather than returned holding no words.
    expect(groupsIn(`[{ label: "a" }, { label: "b" }]`)).toEqual([]);
  });
});
