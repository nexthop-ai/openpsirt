// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Leads } from "./Leads";
import { location, mounted, screen, serve, settle } from "../test/mount";
import { press, tick } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ROWS = [
  {
    place: "abc",
    rule: "clang/unix.Malloc",
    path: "src/a.c",
    line: 7,
    message: "p is leaked",
    stream: "master",
    variant: "broadcom",
    builds: 3,
    opened: "2026-10-01",
    state: "open",
    assigned_to: "kernel",
    assigned_to_name: "Kernel",
    assigned_team: true,
  },
];

async function drawn(at = "/products/sonic/leads", rows: object[] = ROWS) {
  const asked: unknown[] = [];
  serve((path, init) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          kind: "person",
          reach: [{ product: "sonic", reads_internal: true }],
          outcomes: [],
        },
      };
    if (path === "/v1/products/{product}/leads") {
      asked.push((init as { params: { query: unknown } }).params.query);
      return {
        data: {
          items: rows,
          total: 1,
          states: { "not-reproduced": 40, open: 1 },
          waiting: 2,
          ruled: 5,
          past_end_of_life: 3,
        },
      };
    }
    return undefined;
  });
  mount.render(screen(<Leads />, at, "/products/:product/leads"));
  await settle();
  return asked;
}

const text = () => mount.host().textContent ?? "";

describe("the leads", () => {
  it("offers the list as a file asked with the same narrowing", async () => {
    const asked = await drawn(
      "/products/sonic/leads?state=not-reproduced&series=semgrep%2Fdefault",
    );
    expect(asked[0]).toMatchObject({ state: "not-reproduced", series: "semgrep/default" });
    const file = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "CSV",
    );
    const at = new URL(file?.getAttribute("href") ?? "", "http://x");
    expect(at.pathname).toBe("/v1/products/sonic/leads.csv");
    expect(Object.fromEntries(at.searchParams)).toEqual({
      state: "not-reproduced",
      series: "semgrep/default",
    });
  });

  it("lists the queue with each lead opening on the build it is on", async () => {
    await drawn();
    expect(text()).toContain("src/a.c:7");
    expect(text()).toContain("master · broadcom +2");
    const link = mount.host().querySelector<HTMLAnchorElement>("td a");
    expect(link?.getAttribute("href")).toBe(
      "/products/sonic/streams/master/variants/broadcom/leads/abc",
    );
  });

  it("marks a lead in code its run declared third-party", async () => {
    await drawn(undefined, [{ ...ROWS[0], third_party: true }]);
    expect(text()).toContain("Third-party");
  });

  it("marks nothing third-party where the run declared none", async () => {
    await drawn();
    expect(text()).not.toContain("Third-party");
  });

  it("names who holds each lead", async () => {
    await drawn();
    expect(text()).toContain("Kernel · team");
  });

  it("counts what the queue leaves out", async () => {
    await drawn();
    expect(text()).toContain("2 waiting for approval");
    expect(text()).toContain("3 open only past end of life");
    expect(text()).toContain("5 dismissed by a rule");
    expect(text()).toContain("Not reproduced 40");
  });

  it("lists one state's leads, which the address carries", async () => {
    const asked = await drawn();
    await press(mount.host(), "Not reproduced 40");
    await settle();
    expect(location()).toBe("/products/sonic/leads?state=not-reproduced");
    expect(asked.at(-1)).toMatchObject({ state: "not-reproduced" });
  });

  it("narrows to the leads nobody holds, which the address and the file carry", async () => {
    const asked = await drawn("/products/sonic/leads?state=open");
    tick(mount.host(), "Unassigned only");
    await settle();
    expect(location()).toBe("/products/sonic/leads?state=open&assigned=nobody");
    expect(asked.at(-1)).toMatchObject({ state: "open", assigned: "nobody" });
    const file = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "JSON",
    );
    expect(new URL(file?.getAttribute("href") ?? "", "http://x").searchParams.get("assigned")).toBe(
      "nobody",
    );
  });

  it("asks for the build the address names", async () => {
    const asked = await drawn("/products/sonic/leads?stream=master&variant=broadcom");
    expect(asked[0]).toMatchObject({ stream: "master", variant: "broadcom" });
  });
});
