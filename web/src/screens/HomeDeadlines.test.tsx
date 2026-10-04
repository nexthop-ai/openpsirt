// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import type { Who } from "../app/session";
import { Home } from "./Home";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => window.sessionStorage.clear());

const ana: Who = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [],
  outcomes: [],
};

// A page of the deadline list, soonest first as the server orders it, with
// more rows behind it than it carries.
function page(daysLeft: number[], total: number) {
  return { items: daysLeft.map((days_left) => ({ days_left })), total };
}

function tile(label: string): HTMLElement {
  const found = Array.from(mount.host().querySelectorAll<HTMLElement>(".kpi")).find((each) =>
    each.querySelector(".l")?.textContent?.includes(label),
  );
  if (!found) throw new Error(`no tile labelled ${label}`);
  return found;
}

function draw(at: string, scoped: number[], everywhere: number[]) {
  serve((path, init) => {
    if (path !== "/v1/running-out") return { data: { items: [], total: 0 } };
    const query = (init as { params?: { query?: { product?: string } } })?.params?.query;
    return { data: query?.product ? page(scoped, 250) : page(everywhere, 250) };
  });
  mount.render(screen(<Home who={ana} />, at));
}

describe("the front page's deadline tiles", () => {
  it("counts overdue exactly when a cut page reaches a row still due", async () => {
    draw("/", [2, 5, 9], [2, 5, 9]);
    await settle();
    expect(tile("Overdue").querySelector(".n")?.textContent).toBe("0");
    expect(tile("Overdue").querySelector(".d")?.textContent).not.toContain("at least");
    expect(tile("Due soon").querySelector(".n")?.textContent).toBe("3+");
    expect(tile("Due soon").querySelector(".d")?.textContent).toContain("at least");
  });

  it("calls overdue a floor when the whole cut page is overdue", async () => {
    draw("/", [-9, -4, -1], [-9, -4, -1]);
    await settle();
    expect(tile("Overdue").querySelector(".n")?.textContent).toBe("3+");
    expect(tile("Overdue").querySelector(".d")?.textContent).toContain("at least");
  });

  it("counts the all-products overdue figure exactly when its cut page reaches a row still due", async () => {
    draw("/products/p", [-3, 4], [-2, 1, 6]);
    await settle();
    expect(tile("Overdue").querySelector(".d")?.textContent).toBe("1 all products");
    expect(tile("Due soon").querySelector(".d")?.textContent).toBe("2+ all products");
  });

  it("calls the all-products overdue figure a floor when its whole cut page is overdue", async () => {
    draw("/products/p", [-3, 4], [-7, -2]);
    await settle();
    expect(tile("Overdue").querySelector(".d")?.textContent).toBe("2+ all products");
  });
});
