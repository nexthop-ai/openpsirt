// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { BOUND, proseIn, sweep } from "./screen-copy.mjs";

// Both directions per shape — one input that must be reported and one that
// must not — because the failure that matters here is the check going quiet.

const long = Array.from(
  { length: BOUND + 5 },
  (_, i) => `word${"abcdefghijklmnopqrstuvwxyz"[i % 26]}`,
).join(" ");
const short = "Newest first.";

const reported = (source: string) =>
  proseIn(source).found.map((each: { words: number }) => each.words);

describe("standing prose on a screen", () => {
  it("reports a paragraph past the bound", () => {
    expect(reported(`const x = <p className="hint">${long}</p>;`)).toEqual([BOUND + 5]);
  });

  it("passes a paragraph that is a label", () => {
    expect(reported(`const x = <p className="hint">${short}</p>;`)).toEqual([]);
  });

  it("counts prose inside a condition, taking the longer side", () => {
    expect(reported(`const x = <p>{busy ? "${short}" : (<>${long}</>)}</p>;`)).toEqual([BOUND + 5]);
    expect(reported(`const x = <p>{busy && (<>${long}</>)}</p>;`)).toEqual([BOUND + 5]);
  });

  it("does not count what a paragraph computes rather than says", () => {
    expect(
      reported(
        `const x = <p>{rows.map((row) => <span key={row}>{row.name}</span>)} · ${short}</p>;`,
      ),
    ).toEqual([]);
  });

  it("reports a hint span and an empty state's detail, and leaves a tooltip alone", () => {
    expect(reported(`const x = <span className="hint">${long}</span>;`)).toEqual([BOUND + 5]);
    expect(reported(`const x = <Empty title="None." detail="${long}" />;`)).toEqual([BOUND + 5]);
    expect(reported(`const x = <th title="${long}">One pair</th>;`)).toEqual([]);
  });

  it("reports a hint whatever element carries it", () => {
    expect(reported(`const x = <div className="hint">${long}</div>;`)).toEqual([BOUND + 5]);
    expect(reported(`const x = <li className="hint">${long}</li>;`)).toEqual([BOUND + 5]);
    expect(reported(`const x = <div className="hint">${short}</div>;`)).toEqual([]);
  });

  it("counts the text of a template literal around what it interpolates", () => {
    expect(reported(`const x = <p>{\`${long} \${n} ${short}\`}</p>;`)).toEqual([BOUND + 7]);
    expect(reported(`const x = <p>{\`\${n} ${short}\`}</p>;`)).toEqual([]);
  });

  it("counts both sides of a string joined with +", () => {
    expect(reported(`const x = <p>{"${long}" + " ${short}"}</p>;`)).toEqual([BOUND + 7]);
    expect(reported(`const x = <p>{"${short}" + name}</p>;`)).toEqual([]);
  });

  it("counts the longer side of a fallback", () => {
    expect(reported(`const x = <p>{note ?? "${long}"}</p>;`)).toEqual([BOUND + 5]);
    expect(reported(`const x = <p>{note ?? "${short}"}</p>;`)).toEqual([]);
  });

  it("finds no standing prose in the interface, and looked at some", async () => {
    const { found, examined } = await sweep();
    expect(
      examined,
      "no paragraph was found in the interface, so this checked nothing",
    ).toBeGreaterThan(0);
    expect(found).toEqual([]);
  });
});
