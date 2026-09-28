// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InventoryCompare } from "./InventoryCompare";
import { location, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const PAIR = "from=4.2&from_variant=x86&to=4.3&to_variant=x86";

// The component comparison reads its two builds from the address, and each
// kind of change it narrows to is asked of the server.
function served() {
  const asked: string[] = [];
  serve((path, init) => {
    if (path === "/v1/products/{product}/streams") {
      return { data: { items: [{ name: "4.2" }, { name: "4.3" }] } };
    }
    if (path === "/v1/products/{product}/variants") return { data: { items: [{ name: "x86" }] } };
    if (path === "/v1/products/{product}/comparison/inventory") {
      const query = (init as { params: { query: { change?: string } } }).params.query;
      asked.push(query.change ?? "");
      return query.change === "removed"
        ? { data: { items: [], total: 0 } }
        : {
            data: {
              items: [{ name: "zlib", change: "changed", before: ["1.2"], after: ["1.3"] }],
              total: 1,
            },
          };
    }
    return undefined;
  });
  return asked;
}

function draw(query: string) {
  mount.render(
    screen(
      <InventoryCompare />,
      `/products/sonic/comparison/inventory?${query}`,
      "/products/:product/comparison/inventory",
    ),
  );
}

function press(name: string) {
  const button = Array.from(mount.host().querySelectorAll("button")).find(
    (each) => each.textContent === name,
  );
  if (!button) throw new Error(`no ${name} button`);
  act(() => button.click());
}

describe("comparing the components of two builds", () => {
  it("asks for nothing until both builds are picked", async () => {
    const asked = served();
    draw("from=4.2&from_variant=x86");
    await settle();
    expect(mount.host().textContent).toContain("Pick two builds.");
    expect(asked).toEqual([]);
  });

  it("lists what moved between the two builds the address names", async () => {
    served();
    draw(PAIR);
    await settle();
    const later = mount.host().querySelector<HTMLSelectElement>(
      'select[aria-label="Later build stream"]',
    );
    expect(later?.value).toBe("4.3");
    expect(mount.host().textContent).toContain("zlib");
  });

  it("says a kind with nothing in it is empty, and offers everything back", async () => {
    const asked = served();
    draw(PAIR);
    await settle();
    press("Removed");
    await settle();
    expect(asked).toContain("removed");
    expect(mount.host().textContent).toContain("Nothing was removed.");
    press("Show everything");
    await settle();
    expect(location()).not.toContain("change=");
    expect(mount.host().textContent).toContain("zlib");
  });
});
