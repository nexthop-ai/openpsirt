// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { BOUND, namesIn, proseIn, sweep, sweepNames } from "./screen-copy.mjs";

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

const rules = (source: string) => namesIn(source).found.map((each: { rule: string }) => each.rule);

describe("controls and labels that name their thing", () => {
  it("reports a link or a button whose whole text names nothing", () => {
    expect(rules(`const x = <Link to={to}>Read them →</Link>;`)).toEqual(["vague"]);
    expect(rules(`const x = <button type="button">More</button>;`)).toEqual(["vague"]);
  });

  it("passes a link that names where it goes", () => {
    expect(rules(`const x = <Link to={to}>Opened findings →</Link>;`)).toEqual([]);
  });

  it("passes a control whose text is computed", () => {
    expect(rules(`const x = <Link to={to}>{label}</Link>;`)).toEqual([]);
  });

  it("reports a heading or a field label that asks", () => {
    expect(rules(`const x = <h3>What has gone out</h3>;`)).toEqual(["asks"]);
    expect(rules(`const x = <label htmlFor="a">Who</label>;`)).toEqual(["asks"]);
    expect(rules(`const x = <Field label="When it lands"><input /></Field>;`)).toEqual(["asks"]);
  });

  it("reads a label past a child element's attributes", () => {
    expect(
      rules(`const x = <label htmlFor="a">What it is <span style={{ color: c }}>x</span></label>;`),
    ).toEqual(["asks"]);
    expect(rules(`const x = <Link to={to}><Icon name="arrow" /> View</Link>;`)).toEqual(["vague"]);
  });

  it("passes a heading or a label that names", () => {
    expect(rules(`const x = <h3>Sent</h3>;`)).toEqual([]);
    expect(rules(`const x = <Field label="Recipient"><input /></Field>;`)).toEqual([]);
  });

  it("finds none in the interface, and looked at some", async () => {
    const { found, examined } = await sweepNames();
    expect(
      examined,
      "no control, heading or label was found, so this checked nothing",
    ).toBeGreaterThan(0);
    expect(found).toEqual([]);
  });
});
