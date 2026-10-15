// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { AffectedBuilds } from "./FindingBuilds";
import { button, change, press, tick } from "../test/controls";
import { answer, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const releases = [
  { stream: "master", variant: "broadcom", kind: "branch" },
  { stream: "v1.0", variant: "broadcom", kind: "tag" },
  { stream: "v2.0", variant: "broadcom", kind: "tag" },
];

// The issue as the server answers it: the rows on this page, and how many
// there are in all.
function serving(held: { stream: string; variant: string }[], total: number) {
  serve((path) => {
    if (path === "/v1/products/{product}/releases") return { data: { items: releases } };
    if (path === "/v1/issues/{vulnerability}") {
      return {
        data: { items: held.map((each) => ({ ...each, product: "sonic" })), total },
      };
    }
    return undefined;
  });
  return answer("PUT", () => ({ data: { added: 1, closed: 0 } }));
}

async function opened() {
  mount.render(screen(<AffectedBuilds product="sonic" vulnerability="OPENPSIRT-2026-1" />));
  await press(mount.host(), "▸ Which builds this affects");
  await settle();
}

describe("correcting which builds a flaw affects", () => {
  it("writes nothing from a page that is not the whole set", async () => {
    const sent = serving([{ stream: "master", variant: "broadcom" }], 6);
    await opened();
    expect(mount.host().textContent).toContain("more builds than this screen can set");
    expect(mount.host().querySelectorAll('input[type="checkbox"]')).toHaveLength(0);
    expect(() => button(mount.host(), "Set which builds it affects")).toThrow();
    expect(sent()).toHaveLength(0);
  });

  it("sends the whole set it holds, with the build added", async () => {
    const sent = serving([{ stream: "master", variant: "broadcom" }], 1);
    await opened();
    tick(mount.host(), "v1.0");
    await press(mount.host(), "Set which builds it affects");
    await settle();
    expect(sent()).toHaveLength(1);
    expect((sent()[0]?.[1] as { body: unknown }).body).toEqual({
      builds: [
        { stream: "master", variant: "broadcom" },
        { stream: "v1.0", variant: "broadcom" },
      ],
    });
    expect(mount.host().textContent).toContain("1 added · 0 closed as never affected.");
  });

  it("asks why a build comes out before it sends the narrower set", async () => {
    const sent = serving(
      [
        { stream: "master", variant: "broadcom" },
        { stream: "v1.0", variant: "broadcom" },
      ],
      2,
    );
    await opened();
    tick(mount.host(), "v1.0");
    expect(button(mount.host(), "Set which builds it affects").disabled).toBe(true);
    change(mount.host().querySelector("#affects-because"), "Cut before the code arrived.");
    await press(mount.host(), "Set which builds it affects");
    await settle();
    expect((sent()[0]?.[1] as { body: unknown }).body).toEqual({
      builds: [{ stream: "master", variant: "broadcom" }],
      reason: "Cut before the code arrived.",
    });
  });
});
