// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Review, type Plan } from "./Review";
import { mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const PLAN: Plan = {
  build: "sonic · master · broadcom",
  covered: 1,
  total: 1,
  consumers: 1,
  consumersTotal: 1,
  matching: [],
  offered: [],
  reasoning: "Unreachable.",
  versionHere: "1.0",
};

function enter() {
  act(() => {
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  });
}

function button(label: string) {
  const found = Array.from(mount.host().querySelectorAll("button")).find((each) =>
    each.textContent?.includes(label),
  );
  if (!found) throw new Error(`no button ${label}`);
  return found;
}

describe("the review sheet's Enter", () => {
  it("confirms from the sheet itself", () => {
    const onConfirm = vi.fn();
    mount.render(
      <Review
        open
        plan={PLAN}
        busy={false}
        error={null}
        onCancel={() => undefined}
        onConfirm={onConfirm}
      />,
    );
    enter();
    enter();
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("leaves a focused Back button to go back", () => {
    const onConfirm = vi.fn();
    mount.render(
      <Review
        open
        plan={PLAN}
        busy={false}
        error={null}
        onCancel={() => undefined}
        onConfirm={onConfirm}
      />,
    );
    enter();
    act(() => button("Back").focus());
    enter();
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
