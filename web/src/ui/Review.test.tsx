// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Review, type Other, type Plan } from "./Review";
import { mounted } from "../test/mount";
import { press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const other = (
  key: string,
  version: string,
  places: number,
  build = "sonic · 202411 · arm",
): Other => ({
  key,
  build,
  stream: "202411",
  variant: "arm",
  version,
  places,
});

const PLAN: Plan = {
  build: "sonic · master · arm",
  covered: 3,
  total: 5,
  consumers: 2,
  consumersTotal: 3,
  matching: ["sonic · master · x86"],
  offered: [other("a", "1.1", 4), other("b", "", 0, "this build")],
  reasoning: "Unreachable from any entry point.\nSecond line.",
  versionHere: "1.0",
};

function drawn(plan: Plan = PLAN) {
  const onConfirm = vi.fn<(applied: Other[]) => void>();
  const onCancel = vi.fn();
  mount.render(
    <Review open plan={plan} busy={false} error={null} onCancel={onCancel} onConfirm={onConfirm} />,
  );
  return { onConfirm, onCancel };
}

const text = () => mount.host().textContent ?? "";

describe("the reach of a decision, reviewed before it is written", () => {
  it("submits only the other versions ticked, and counts the records each writes", async () => {
    const { onConfirm } = drawn();
    expect(text()).toContain("2 of 3 consumers");
    expect(text()).toContain("2 places left open by you");
    expect(text()).toContain("What you wrote: Unreachable from any entry point.");
    const [first] = Array.from(
      mount.host().querySelectorAll<HTMLInputElement>('input[type="checkbox"]'),
    );
    await act(async () => first?.click());
    await press(mount.host(), "Review and submit → ↵");
    // The places here and the places in the version ticked.
    expect(text()).toContain("7 records written");
    expect(text()).toContain("Left undecided");
    expect(text()).toContain("unstated in this build");
    await press(mount.host(), "Confirm and submit ↵");
    expect(onConfirm).toHaveBeenCalledWith([PLAN.offered[0]]);
  });

  it("counts a version with no places stated as one record", async () => {
    drawn();
    const boxes = Array.from(
      mount.host().querySelectorAll<HTMLInputElement>('input[type="checkbox"]'),
    );
    await act(async () => boxes[1]?.click());
    await press(mount.host(), "Review and submit → ↵");
    expect(text()).toContain("4 records written");
  });

  it("cancels on Escape and on the backdrop", () => {
    const { onCancel } = drawn();
    act(() => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    });
    act(() => {
      mount.host().querySelector<HTMLElement>(".backdrop")?.click();
    });
    expect(onCancel).toHaveBeenCalledTimes(2);
  });

  it("says no other build matches and none holds another version", () => {
    drawn({ ...PLAN, matching: [], offered: [] });
    expect(text()).toContain("No other build matches this one's versions and chain.");
    expect(text()).toContain("No other build holds this issue at a different version.");
  });
});
