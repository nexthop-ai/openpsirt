// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Leads } from "./Leads";
import { location, mounted, screen, serve, settle } from "../test/mount";
import { press } from "../test/controls";

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
  },
];

async function drawn(at = "/products/sonic/leads") {
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
        data: { items: ROWS, total: 1, states: { baseline: 40, open: 1 }, waiting: 2, ruled: 5 },
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
  it("lists the queue with each lead opening on the build it is on", async () => {
    await drawn();
    expect(text()).toContain("src/a.c:7");
    expect(text()).toContain("master · broadcom +2");
    const link = mount.host().querySelector<HTMLAnchorElement>("td a");
    expect(link?.getAttribute("href")).toBe(
      "/products/sonic/streams/master/variants/broadcom/leads/abc",
    );
  });

  it("counts what the queue leaves out", async () => {
    await drawn();
    expect(text()).toContain("2 waiting for approval");
    expect(text()).toContain("5 dismissed by a rule");
    expect(text()).toContain("Baseline 40");
  });

  it("lists one state's leads, which the address carries", async () => {
    const asked = await drawn();
    await press(mount.host(), "Baseline 40");
    await settle();
    expect(location()).toBe("/products/sonic/leads?state=baseline");
    expect(asked.at(-1)).toMatchObject({ state: "baseline" });
  });

  it("asks for the build the address names", async () => {
    const asked = await drawn("/products/sonic/leads?stream=master&variant=broadcom");
    expect(asked[0]).toMatchObject({ stream: "master", variant: "broadcom" });
  });
});
