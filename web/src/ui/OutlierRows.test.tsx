// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it, vi } from "vitest";
import { OutlierRows } from "./OutlierRows";
import { mounted } from "../test/mount";

const mount = mounted();

const rows = [
  {
    decision_id: 1,

    vulnerability: "CVE-2026-0001",
    why: ["fixable", "off the term"],
  },
  { decision_id: 2, vulnerability: "CVE-2026-0002", why: [] },
];

describe("the rows that do not match the rest", () => {
  it("ticks the rows being held back and says why each stands out", () => {
    mount.render(<OutlierRows rows={rows} holding={new Set([2])} onToggle={() => {}} />);
    const boxes = mount.host().querySelectorAll<HTMLInputElement>("input[type=checkbox]");
    expect([...boxes].map((box) => box.checked)).toEqual([false, true]);
    expect(mount.host().textContent).toContain("fixable, off the term");
  });

  it("hands back the row a box was ticked on", () => {
    const toggled = vi.fn();
    mount.render(<OutlierRows rows={rows} holding={new Set()} onToggle={toggled} />);
    const box = mount.host().querySelector<HTMLInputElement>("input[type=checkbox]");
    act(() => box?.click());
    expect(toggled).toHaveBeenCalledWith(rows[0], true);
  });
});
