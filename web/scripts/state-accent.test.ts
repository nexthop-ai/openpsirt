// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { stateInAccent, sweep } from "./state-accent.mjs";

describe("a state drawn in the accent", () => {
  it("reports a pressed control filled with the accent", () => {
    const css = `.seg button[aria-pressed="true"] { background: var(--accent); }`;
    expect(stateInAccent("x.css", css).found).toEqual([`x.css: .seg button[aria-pressed="true"]`]);
  });

  it("reports a tinted row marked on", () => {
    expect(
      stateInAccent("x.css", `tr.row.on > td { background: var(--accent-soft); }`).found,
    ).toEqual(["x.css: tr.row.on > td"]);
  });

  it("passes a state drawn in ink", () => {
    const css = `.seg button[aria-pressed="true"] { background: var(--ink); color: var(--canvas); }`;
    expect(stateInAccent("x.css", css).found).toEqual([]);
  });

  it("passes the accent on hover and focus", () => {
    const css = `.choice-card:hover { border-color: var(--accent-line); }
      .choice-card[aria-checked="true"]:focus-visible { outline: 2px solid var(--accent); }`;
    expect(stateInAccent("x.css", css).found).toEqual([]);
  });

  it("finds no state drawn in the accent in any stylesheet", () => {
    const { examined, found } = sweep();
    expect(examined, "no style rules were found, so this checked nothing").toBeGreaterThan(0);
    expect(found).toEqual([]);
  });
});
