// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { doneButTrouble, doneClasses, sweep } from "./state-colors.mjs";

const DONE = new Set(["agreed", "closed"]);
const check = (text: string) => doneButTrouble("x.tsx", text, DONE) as string[];

describe("a hand-written state chip", () => {
  it("reports a failure drawn as done", () => {
    expect(check(`<span className="state closed" title={why}>failing</span>`)).toEqual([
      "x.tsx:1: failing",
    ]);
  });

  it("reports a failure drawn in any done class", () => {
    expect(check(`<span className="state agreed">refused</span>`)).toEqual(["x.tsx:1: refused"]);
  });

  it("passes a done chip that says it is done", () => {
    expect(check(`<span className="state closed">scanned</span>`)).toEqual([]);
  });

  it("passes a failure drawn as bad", () => {
    expect(check(`<span className="state bad">stopped</span>`)).toEqual([]);
  });
});

describe("the record a computed chip reads", () => {
  it("reports a failure given a done class", () => {
    expect(check(`const shown = { cls: "agreed", said: "failed" };`)).toEqual(["x.tsx:1: failed"]);
  });

  it("reads a template's literal words", () => {
    expect(check('const s = { tone: "closed", label: `${n} refused` };')).toEqual([
      "x.tsx:1: refused",
    ]);
  });

  it("passes a done class with done words", () => {
    expect(check(`const shown = { cls: "agreed", said: "Approved" };`)).toEqual([]);
  });

  it("passes a failure given a class that is not done", () => {
    expect(check(`const shown = { cls: "bad", said: "failed" };`)).toEqual([]);
  });
});

describe("the classes taken as done", () => {
  it("is every state class whose color is the ok token", () => {
    const css = `.state.agreed { --c: var(--ok); } .state.closed { --c: var(--ok); }
      .state.bad { --c: var(--sev-critical); } .other { --c: var(--ok); }`;
    expect([...(doneClasses(css) as Set<string>)].sort()).toEqual(["agreed", "closed"]);
  });
});

describe("the interface", () => {
  it("draws no failure as done, and looked", () => {
    const { files, done, found } = sweep();
    expect(files, "no screens were found, so this checked nothing").toBeGreaterThan(0);
    expect(done, "no state class is drawn as done, so this checked nothing").not.toEqual([]);
    expect(found).toEqual([]);
  });
});
