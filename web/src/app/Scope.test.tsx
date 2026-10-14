// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Scope } from "./Scope";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());
afterEach(() => vi.restoreAllMocks());

function options(): HTMLButtonElement[] {
  return Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button.opt"));
}

describe("the scope panel on a screen that needs a build", () => {
  it("offers no variant until a branch or tag is picked", async () => {
    serve((path) => {
      if (path === "/v1/products")
        return { data: { items: [{ name: "sonic" }, { name: "edgeos" }] } };
      if (path === "/v1/products/{product}/variants") return { data: { items: [{ name: "arm" }] } };
      return { data: { items: [] } };
    });
    mount.render(screen(<Scope />, "/products/sonic/streams/master/variants/x/inventories"));
    await settle();
    await act(async () => mount.host().querySelector<HTMLButtonElement>("button.scope")?.click());
    await settle();
    await act(async () =>
      options()
        .find((each) => each.textContent === "edgeos")
        ?.click(),
    );
    await settle();
    const variant = options().find((each) => each.textContent === "arm");
    expect(variant).toBeDefined();
    expect(variant?.disabled).toBe(true);
  });
});
