// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Compare } from "./Compare";
import { press, tick } from "../test/controls";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const PATTERN = "/products/:product/compare";
const PAIR = "from=202411&from_variant=broadcom&to=master&to_variant=broadcom";

const comparison = {
  fixed: [{ vulnerability: "CVE-2026-1", component: "libnl", because: "upgraded" }],
  closed_not_fixed: [
    { vulnerability: "CVE-2026-2", component: "zlib", because: "unexplained", closed_by_run: 7 },
  ],
  newly_present: [],
  still_present: [
    { vulnerability: "CVE-2026-3", component: "curl", state: "agreed", outcome: "not-affected" },
    { vulnerability: "CVE-2026-4", component: "curl", state: "open" },
  ],
};

// The reads the screen makes, answered, and every one it asked for.
function serving() {
  return serve((path) => {
    if (path === "/v1/products/{product}/comparison") return { data: comparison };
    if (path === "/v1/products/{product}/comparison/notes") return { data: "## Fixed\n" };
    if (path === "/v1/products/{product}/releases") return { data: { items: [] } };
    return { data: { items: [], total: 0 } };
  });
}

type Asked = [string, { params: { query?: Record<string, unknown> } }];

function queriesOf(spy: ReturnType<typeof serving>, path: string) {
  return (spy.mock.calls as unknown as Asked[])
    .filter(([each]) => each === path)
    .map(([, init]) => init.params.query);
}

describe("comparing two builds", () => {
  it("asks for the pair picked, public findings only, and draws each column", async () => {
    const spy = serving();
    mount.render(screen(<Compare />, `/products/sonic/compare?${PAIR}`, PATTERN));
    await settle();
    expect(queriesOf(spy, "/v1/products/{product}/comparison").at(-1)).toEqual({
      from: "202411",
      from_variant: "broadcom",
      to: "master",
      to_variant: "broadcom",
    });
    const counts = Array.from(mount.host().querySelectorAll(".col header .n")).map(
      (each) => each.textContent,
    );
    expect(counts).toEqual(["1", "1", "0", "2"]);
    expect(mount.host().textContent).toContain("the run that stopped");
  });

  it("includes undisclosed findings only once asked to", async () => {
    const spy = serving();
    mount.render(screen(<Compare />, `/products/sonic/compare?${PAIR}`, PATTERN));
    await settle();
    await press(mount.host(), "Include undisclosed");
    await settle();
    expect(queriesOf(spy, "/v1/products/{product}/comparison").at(-1)).toMatchObject({
      include_undisclosed: true,
    });
  });

  it("writes release notes for the same question, and only when asked", async () => {
    const spy = serving();
    mount.render(screen(<Compare />, `/products/sonic/compare?${PAIR}`, PATTERN));
    await settle();
    expect(queriesOf(spy, "/v1/products/{product}/comparison/notes")).toEqual([]);
    await press(mount.host(), "Write release notes");
    await settle();
    expect(queriesOf(spy, "/v1/products/{product}/comparison/notes")).toEqual(
      queriesOf(spy, "/v1/products/{product}/comparison").slice(-1),
    );
    expect(mount.host().querySelector("pre.notes")?.textContent).toBe("## Fixed\n");
  });

  it("narrows what is unchanged to what nobody has agreed to", async () => {
    serving();
    mount.render(screen(<Compare />, `/products/sonic/compare?${PAIR}`, PATTERN));
    await settle();
    tick(mount.host(), "Only what nobody has agreed to");
    const still = mount.host().querySelector(".col.still");
    expect(still?.querySelector(".n")?.textContent).toBe("1");
    expect(still?.textContent).toContain("CVE-2026-4");
    expect(still?.textContent).not.toContain("CVE-2026-3");
  });

  it("asks nothing until two builds are picked", async () => {
    const spy = serving();
    mount.render(screen(<Compare />, "/products/sonic/compare", PATTERN));
    await settle();
    expect(mount.host().textContent).toContain("Pick two builds.");
    expect(queriesOf(spy, "/v1/products/{product}/comparison")).toEqual([]);
  });
});
