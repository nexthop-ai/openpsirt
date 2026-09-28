// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error - plain ESM with no types of its own
import { indexHtml } from "../../scripts/source.mjs";
import { applyLook, LOOKS } from "./look";

// The page stamps the look before anything paints, in a script that cannot
// import this module. What it reads has to be what this module keeps: a look
// it does not know is replaced by the system's on every load, and a key it does
// not read disables the stamp entirely.
describe("the look stamped before the first paint", () => {
  beforeEach(() => window.localStorage.clear());

  it("is read from the key a chosen look is kept under", () => {
    applyLook("dark");
    const key = window.localStorage.key(0);
    const read = /getItem\(("[^"]*")\)/.exec(indexHtml() as string);
    expect(read).not.toBeNull();
    expect(JSON.parse(read?.[1] ?? "null")).toBe(key);
  });

  it("knows every look somebody can choose", () => {
    const known = /var looks = (\[[^\]]*\]);/.exec(indexHtml() as string);
    expect(known).not.toBeNull();
    expect(JSON.parse(known?.[1] ?? "null")).toEqual(LOOKS.map((each) => each.name));
  });
});
