// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { rulesIn } from "./class-rules.mjs";
// @ts-expect-error - plain ESM with no types of its own
import { stylesheets } from "./source.mjs";

// A class reached as a modifier — `.state.warn`, `.timeline.past` — must not
// also have a bare rule that draws a box. Every element carrying the modifier
// carries the bare rule too, at the same specificity, so a later bare rule
// replaces the display, spacing, border and background of the thing it
// modifies: a chip in a table cell draws as a block-level callout.
const box =
  /(^|[\s;])(display|margin(-[a-z]+)?|padding(-[a-z]+)?|border(-[a-z]+)?|background(-[a-z]+)?)\s*:/;

function boxedModifiers(declared: Map<string, string>, modifiers: Map<string, string>): string[] {
  return [...modifiers.keys()].filter((name) => box.test(declared.get(name) ?? "")).sort();
}

describe("a modifier class", () => {
  it("has no bare rule of its own that draws a box", () => {
    const into = { declared: new Map<string, string>(), modifiers: new Map<string, string>() };
    for (const text of stylesheets() as string[]) rulesIn(text, into);
    if (into.modifiers.size === 0)
      throw new Error("no modifiers were read, so this checked nothing");
    expect(boxedModifiers(into.declared, into.modifiers)).toEqual([]);
  });

  it("is reported where its bare rule sets a display or a padding", () => {
    const into = rulesIn(`.state.warn { color: red; } .warn { display: flex; padding: 8px; }`);
    expect(boxedModifiers(into.declared, into.modifiers)).toEqual(["warn"]);
  });

  it("is not reported where its bare rule only sets a font", () => {
    const into = rulesIn(`.linkish.id { color: red; } .id { font-family: monospace; }`);
    expect(boxedModifiers(into.declared, into.modifiers)).toEqual([]);
  });
});
