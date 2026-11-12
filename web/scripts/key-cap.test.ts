// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { keyCapRules } from "./key-cap.mjs";

// A primary button is ink with canvas text, and the two swap between the light
// and the dark look. A key cap on it drawn in a fixed color vanishes in one of
// them, so it is drawn in the button's own text color.
describe("the key cap on a primary button", () => {
  it("is drawn in the button's text color in every look", () => {
    const caps = keyCapRules() as { selector: string; body: string }[];
    expect(caps, "no rule draws the key cap, so this checked nothing").toHaveLength(1);
    const body = caps[0]?.body ?? "";
    expect(body).toMatch(/border-color:[^;]*var\(--canvas\)/);
    expect(body).toMatch(/background:[^;]*var\(--canvas\)/);
    expect(body).not.toMatch(/rgb\(|#[0-9a-f]{3,8}\b|white/i);
  });
});
