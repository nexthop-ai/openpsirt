// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Scope } from "./Scope";
import { location, mounted, screen, serve, settle, type Answer } from "../test/mount";

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

// The catalog every case below picks from: one product with one branch, built
// as one variant.
function catalog(path: string): Answer | undefined {
  if (path === "/v1/products") return { data: { items: [{ name: "sonic" }] } };
  if (path === "/v1/products/{product}/streams")
    return { data: { items: [{ name: "master", kind: "branch" }] } };
  if (path === "/v1/products/{product}/variants") return { data: { items: [{ name: "arm" }] } };
  if (path === "/v1/products/{product}/streams/{stream}/variants")
    return { data: { items: [{ name: "arm" }, { name: "old", retired: true }] } };
  return { data: { items: [] } };
}

async function opened(at: string, answer = catalog) {
  serve(answer);
  mount.render(screen(<Scope />, at));
  await settle();
  await act(async () => mount.host().querySelector<HTMLButtonElement>("button.scope")?.click());
  await settle();
}

async function pick(text: string) {
  await act(async () =>
    options()
      .find((each) => each.textContent?.startsWith(text))
      ?.click(),
  );
  await settle();
}

function kept(): unknown {
  return JSON.parse(window.sessionStorage.getItem("openpsirt.scope") ?? "null");
}

const expanded = () =>
  mount.host().querySelector<HTMLButtonElement>("button.scope")?.getAttribute("aria-expanded");

describe("applying a pick", () => {
  it("moves the findings list to the product picked and keeps the panel open", async () => {
    await opened("/findings");
    await pick("sonic");
    expect(location()).toBe("/products/sonic/findings");
    expect(kept()).toEqual({ product: "sonic" });
    expect(expanded()).toBe("true");
  });

  it("carries a branch on the product's list as a filter", async () => {
    await opened("/findings");
    await pick("sonic");
    await pick("master");
    expect(location()).toBe("/products/sonic/findings?stream=master");
  });

  it("closes on the variant, the last level", async () => {
    await opened("/findings");
    await pick("sonic");
    await pick("master");
    await pick("arm");
    expect(location()).toBe("/products/sonic/streams/master/variants/arm/findings");
    expect(kept()).toEqual({ product: "sonic", stream: "master", variant: "arm" });
    expect(expanded()).toBe("false");
  });

  it("offers no retired variant", async () => {
    await opened("/findings");
    await pick("sonic");
    await pick("master");
    expect(options().map((each) => each.textContent)).not.toContain("old");
  });

  it("remembers the pick and stays on a screen about no product", async () => {
    await opened("/settings");
    await pick("sonic");
    expect(location()).toBe("/settings");
    expect(kept()).toEqual({ product: "sonic" });
  });

  it("swaps the build on a screen about one build and keeps the screen", async () => {
    await opened("/products/edgeos/streams/main/variants/x86/inventories");
    await pick("sonic");
    expect(location()).toBe("/products/edgeos/streams/main/variants/x86/inventories");
    await pick("master");
    await pick("arm");
    expect(location()).toBe("/products/sonic/streams/master/variants/arm/inventories");
  });

  it("says the products could not be read rather than listing none", async () => {
    await opened("/findings", (path) =>
      path === "/v1/products" ? { status: 503 } : catalog(path),
    );
    expect(mount.host().textContent).toContain("Couldn\u2019t read the products.");
    expect(mount.host().textContent).not.toContain("You can reach no product yet.");
  });
});
