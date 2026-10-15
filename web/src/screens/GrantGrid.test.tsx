// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GrantGrid } from "./GrantGrid";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

type Held = Parameters<typeof GrantGrid>[0]["holds"];

// The grid over two products, one shown under a display name, with the four
// acts recorded rather than sent.
async function drawn(holds: Held) {
  serve((path) =>
    path === "/v1/products"
      ? { data: { items: [{ name: "sonic", display_name: "Network OS" }, { name: "edgeos" }] } }
      : undefined,
  );
  const acts = {
    onGrant: vi.fn(),
    onWithdraw: vi.fn(),
    onGrantEverywhere: vi.fn(),
    onWithdrawEverywhere: vi.fn(),
  };
  mount.render(screen(<GrantGrid holds={holds} busy={false} {...acts} />));
  await settle();
  return acts;
}

function box(label: string): HTMLInputElement {
  const found = mount.host().querySelector<HTMLInputElement>(`input[aria-label="${label}"]`);
  if (!found) throw new Error(`no box ${label}`);
  return found;
}

const click = (label: string) => act(async () => box(label).click());

describe("the grant grid", () => {
  it("withdraws a role held under the product's display name by its API name", async () => {
    const acts = await drawn([{ product: "Network OS", role: "approver" }]);
    expect(box("Approver on sonic").checked).toBe(true);
    await click("Approver on sonic");
    expect(acts.onWithdraw).toHaveBeenCalledWith("sonic", "approver");
    expect(acts.onGrant).not.toHaveBeenCalled();
  });

  it("grants a role not held", async () => {
    const acts = await drawn([]);
    await click("Read, private on edgeos");
    expect(acts.onGrant).toHaveBeenCalledWith("edgeos", "private-read");
  });

  it("locks a product cell the estate grant covers, and withdraws that grant where it was given", async () => {
    const acts = await drawn([{ everywhere: true, role: "public-read" }]);
    expect(box("Read, public on edgeos").checked).toBe(true);
    expect(box("Read, public on edgeos").disabled).toBe(true);
    await click("Read, public on every product");
    expect(acts.onWithdrawEverywhere).toHaveBeenCalledWith("public-read");
  });

  it("locks a role a group gives", async () => {
    await drawn([{ product: "sonic", role: "assigner", source: "derived" }]);
    expect(box("Assigner on sonic").disabled).toBe(true);
  });

  it("marks the estate box part-held where only some products hold the role", async () => {
    const acts = await drawn([{ product: "edgeos", role: "approver" }]);
    expect(box("Approver on every product").indeterminate).toBe(true);
    expect(box("Approver on every product").checked).toBe(false);
    await click("Approver on every product");
    expect(acts.onGrantEverywhere).toHaveBeenCalledWith("approver");
  });

  it("does not count a role that is not in force", async () => {
    await drawn([{ product: "sonic", role: "approver", effective: false }]);
    expect(box("Approver on sonic").checked).toBe(false);
  });

  it("marks an approver cell that would reach nothing without a read role", async () => {
    await drawn([]);
    expect(box("Approver on sonic").title).toContain("Reaches nothing");
  });
});
