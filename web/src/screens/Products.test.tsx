// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Products } from "./Products";
import { answer, mounted, screen, serve, settle } from "../test/mount";
import { change, labeled, only, press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const person = (admin: boolean) => ({
  identity: "ana",
  name: "Ana",
  admin,
  kind: "person" as const,
  reach: [],
  outcomes: [],
});

const SONIC = {
  name: "sonic",
  display_name: "SONiC",
  branches: 2,
  tags: 1,
  variants: 3,
  open: 12,
  triage_floor: "",
  pair_share: 0,
  pair_approvers: 0,
};

async function drawn(admin = true) {
  serve((path) => {
    if (path === "/v1/products") return { data: { items: [SONIC] } };
    if (path === "/v1/scanning") return { data: { items: [], quiet_after_days: 7 } };
    return undefined;
  });
  const writes = {
    post: answer("POST", () => ({ data: {} })),
    patch: answer("PATCH", () => ({ data: {} })),
    put: answer("PUT", () => ({ data: {} })),
    del: answer("DELETE", () => ({ data: {} })),
  };
  mount.render(screen(<Products who={person(admin)} />, "/products"));
  await settle();
  return writes;
}

const host = () => mount.host();

describe("the products an administrator manages", () => {
  it("sends a display name alone when the name was left as it was", async () => {
    const writes = await drawn();
    await press(host(), "Edit");
    change(labeled(host(), "Shown as"), "SONiC 2");
    await press(host(), "Save");
    await settle();
    const [path, init] = only(writes.patch);
    expect(path).toBe("/v1/products/{product}");
    expect(init.params?.path).toEqual({ product: "sonic" });
    expect(init.body).toEqual({ display_name: "SONiC 2" });
  });

  it("sends the new name when it changed", async () => {
    const writes = await drawn();
    await press(host(), "Edit");
    change(labeled(host(), "Name"), "sonic-os");
    await press(host(), "Save");
    await settle();
    expect(only(writes.patch)[1].body).toEqual({ name: "sonic-os", display_name: "SONiC" });
  });

  it("declares a product with no display name where none was typed", async () => {
    const writes = await drawn();
    await press(host(), "Add product");
    const drawer = host();
    change(labeled(drawer, "Name"), " edgeos ");
    const add = Array.from(drawer.querySelectorAll("button")).filter(
      (each) => each.textContent?.trim() === "Add product",
    );
    await act(async () => add.at(-1)?.click());
    await settle();
    expect(only(writes.post)[1].body).toEqual({ name: "edgeos", display_name: undefined });
  });

  it("sets the triage line picked", async () => {
    const writes = await drawn();
    change(
      host().querySelector<HTMLSelectElement>(
        'select[aria-label="What sonic considers worth triaging"]',
      ),
      "high",
    );
    await settle();
    const [path, init] = only(writes.put);
    expect(path).toBe("/v1/products/{product}/triage-floor");
    expect(init.body).toEqual({ floor: "high" });
  });

  it("sends pair thresholds as numbers, and a blank one as the deployment's", async () => {
    const writes = await drawn();
    await press(host(), "deployment’s");
    change(
      host().querySelector<HTMLInputElement>(
        'input[aria-label="Share of sonic\'s agreements one pair may give, as a percentage"]',
      ),
      "40",
    );
    await press(host(), "Save");
    await settle();
    const [path, init] = only(writes.put);
    expect(path).toBe("/v1/products/{product}/pair-thresholds");
    expect(init.body).toEqual({ share: 40, approvers: 0 });
  });

  it("retires the product the row names", async () => {
    const writes = await drawn();
    await press(host(), "Retire");
    await settle();
    expect(only(writes.del)[1].params?.path).toEqual({ product: "sonic" });
  });
});

describe("the products somebody else reads", () => {
  it("offers no control that changes a product", async () => {
    await drawn(false);
    expect(host().querySelector("select")).toBeNull();
    const words = Array.from(host().querySelectorAll("button")).map((each) => each.textContent);
    expect(words).not.toContain("Edit");
    expect(words).not.toContain("Retire");
    expect(host().textContent).toContain("deployment’s");
  });
});
