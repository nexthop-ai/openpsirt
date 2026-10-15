// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReasonEditor } from "./ReasonEditor";
import { belongTo } from "../app/drafts";
import { answer, mounted, screen, serve, settle } from "../test/mount";
import { button, only, press, change } from "../test/controls";

const mount = mounted();

beforeEach(() => {
  window.localStorage.clear();
  belongTo("oidc:ana");
});
afterEach(() => vi.restoreAllMocks());

async function drawn(state: string, approved = true) {
  serve(() => ({ data: { items: [] } }));
  const writes = {
    put: answer("PUT", () => ({ data: {} })),
    del: answer("DELETE", () => ({ data: {} })),
  };
  const onDone = vi.fn();
  mount.render(
    screen(
      <ReasonEditor
        claimId={12}
        reasoning="Unreachable."
        state={state}
        approved={approved}
        about={{ product: "sonic", vulnerability: "CVE-2026-1" }}
        onDone={onDone}
      />,
    ),
  );
  await settle();
  return { ...writes, onDone };
}

const text = () => mount.host().textContent ?? "";

describe("revising and withdrawing a claim's reasoning", () => {
  it("says revising withdraws an approval, and sends the new words for this claim", async () => {
    const { put, onDone } = await drawn("agreed");
    expect(text()).toContain("Revising withdraws the approval");
    await press(mount.host(), "Revise reasoning");
    const field = mount.host().querySelector<HTMLTextAreaElement>("textarea");
    expect(field?.value).toBe("Unreachable.");
    change(field, "   ");
    expect(button(mount.host(), "Save revision").disabled).toBe(true);
    change(field, "Unreachable, and the module is not loaded.");
    await press(mount.host(), "Save revision");
    await settle();
    const [path, init] = only(put);
    expect(path).toBe("/v1/claims/{id}/reasoning");
    expect(init.params?.path).toEqual({ id: 12 });
    expect(init.body).toEqual({ reasoning: "Unreachable, and the module is not loaded." });
    expect(onDone).toHaveBeenCalled();
  });

  it("withdraws the claim named", async () => {
    const { del } = await drawn("waiting", false);
    expect(text()).toContain("Withdrawing needs nobody");
    expect(text()).not.toContain("Revising withdraws the approval");
    await press(mount.host(), "Withdraw");
    await settle();
    expect(only(del)[1].params?.path).toEqual({ id: 12 });
  });

  it("offers nothing to change on a claim that has ended", async () => {
    await drawn("withdrawn");
    expect(
      Array.from(mount.host().querySelectorAll("button")).map((b) => b.textContent),
    ).not.toContain("Withdraw");
  });
});
