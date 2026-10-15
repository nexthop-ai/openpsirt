// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { belongTo } from "../app/drafts";
import { Component } from "./Component";
import { button, change, press } from "../test/controls";
import { accept, location, mounted, screen, serve, settle, type Sent } from "../test/mount";

const mount = mounted();

beforeEach(() => {
  window.localStorage.clear();
  belongTo("oidc:ana");
});

afterEach(() => vi.restoreAllMocks());

const PATTERN = "/products/:product/components/:component";

// One build shipping libnl at a version, with what is open there and the
// versions a scanner named as fixing it.
function build(stream: string, variant: string, version: string, upgrades: string[]) {
  return {
    stream,
    variant,
    version,
    source: "libnl",
    ecosystem: "deb",
    issues: 4,
    fixable: 3,
    packages: [{ name: "libnl", version, issues: 4 }],
    upgrades: upgrades.map((to) => ({ to, ordered: true, reached: 3 })),
  };
}

function serving(items: unknown[]) {
  serve((path) =>
    path === "/v1/products/{product}/components/{component}"
      ? { data: { items } }
      : { data: { items: [], total: 0 } },
  );
}

function chip(stream: string, variant: string): HTMLButtonElement {
  const found = Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button.vchip")).find(
    (each) => each.textContent?.includes(stream) && each.textContent.includes(variant),
  );
  if (!found) throw new Error(`no release ${stream} ${variant}`);
  return found;
}

describe("scheduling an upgrade of a component", () => {
  it("promises the version picked, for the releases left ticked, at the version on screen", async () => {
    serving([
      build("master", "broadcom", "3.7", ["3.9", "3.8"]),
      build("master", "mellanox", "3.7", ["3.9", "3.8"]),
      build("202411", "broadcom", "3.5", ["3.9"]),
    ]);
    const sent = accept(() => ({
      data: { claim_id: 9, decisions: 2, issues: 2, waiting: false, held: false },
    }));
    mount.render(
      screen(
        <Component />,
        "/products/sonic/components/libnl?stream=master&variant=broadcom&version=3.7",
        PATTERN,
      ),
    );
    await settle();
    expect(button(mount.host(), "Schedule for 2").disabled).toBe(true);
    act(() => chip("master", "mellanox").click());
    const offered = Array.from(mount.host().querySelectorAll<HTMLButtonElement>(".tomove button"));
    act(() => offered.find((each) => each.querySelector(".id")?.textContent === "3.8")?.click());
    change(mount.host().querySelector<HTMLInputElement>('input[type="date"]'), "2026-12-01");
    change(mount.host().querySelector("textarea"), "The packaged fix.");
    await press(mount.host(), "Schedule for 1");
    await settle();
    const [path, init] = sent()[0] as Sent;
    expect(path).toBe("/v1/products/{product}/components/{component}/upgrade");
    expect(init).toEqual({
      params: { path: { product: "sonic", component: "libnl" } },
      body: {
        to: "3.8",
        version: "3.7",
        by: "2026-12-01",
        reasoning: "The packaged fix.",
        builds: [{ stream: "master", variant: "broadcom" }],
      },
    });
    expect(mount.host().textContent).toContain("Recorded against 2 places across 2 issues.");
  });

  it("opens on the other version's own build when that version is picked", async () => {
    serving([
      build("master", "broadcom", "3.7", ["3.9"]),
      build("202411", "broadcom", "3.5", ["3.9"]),
    ]);
    mount.render(screen(<Component />, "/products/sonic/components/libnl", PATTERN));
    await settle();
    expect(mount.host().textContent).toContain("Shipped at 2 versions");
    const other = Array.from(mount.host().querySelectorAll("button")).find((each) =>
      each.textContent?.startsWith("3.5"),
    );
    act(() => other?.click());
    await settle();
    expect(location()).toContain("version=3.5");
    expect(location()).toContain("stream=202411");
  });

  it("offers a judgment rather than an empty form when nothing fixes it", async () => {
    serving([build("master", "broadcom", "3.7", [])]);
    mount.render(screen(<Component />, "/products/sonic/components/libnl", PATTERN));
    await settle();
    expect(mount.host().textContent).toContain("There is nothing to upgrade to");
    expect(() => button(mount.host(), "Schedule for 1")).toThrow();
  });

  it("says no build ships a name nothing carries", async () => {
    serving([]);
    mount.render(screen(<Component />, "/products/sonic/components/libnl", PATTERN));
    await settle();
    expect(mount.host().textContent).toContain("No build of this product ships it.");
  });
});
