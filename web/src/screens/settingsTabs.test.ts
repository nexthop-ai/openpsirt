// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { tabOf, tally } from "./settingsTabs";

describe("the settings tabs", () => {
  it("opens the tab the address names", () => {
    expect(tabOf("scanning", false)).toBe("scanning");
  });
  it("opens the first section for an address naming no tab", () => {
    expect(tabOf("nonsense", true)).toBe("deadlines");
    expect(tabOf(undefined, true)).toBe("deadlines");
  });
  it("keeps an administrator's tab from anybody else", () => {
    expect(tabOf("webhooks", true)).toBe("webhooks");
    expect(tabOf("webhooks", false)).toBe("deadlines");
  });
  it("counts what differs from the shipped value, and otherwise what a tab holds", () => {
    const items = [
      { section: "triage", default: true },
      { section: "triage", default: false },
      { section: "limits", default: true },
      { section: "limits", default: true },
    ];
    expect(tally(items, "triage")).toBe("1 changed");
    expect(tally(items, "limits")).toBe("2");
  });
});
