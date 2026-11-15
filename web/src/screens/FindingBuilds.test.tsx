// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { AffectedBuilds } from "./FindingBuilds";
import { button, change, press, tick } from "../test/controls";
import { answer, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

const releases = [
  { branch_or_tag: "master", variant: "broadcom", kind: "branch" },
  { branch_or_tag: "v1.0", variant: "broadcom", kind: "tag" },
  { branch_or_tag: "v2.0", variant: "broadcom", kind: "tag" },
];

// The builds the flaw is open at as the server answers them, in one read, with
// whether it is open at more than one write names. `asked` records the product
// each read named.
function serving(held: { branch_or_tag: string; variant: string }[], more = false) {
  const asked: string[] = [];
  serve((path, init) => {
    if (path === "/v1/products/{product}/releases") return { data: { items: releases } };
    if (path === "/v1/products/{product}/issues/{issue}/builds") {
      asked.push((init as { params: { path: { product: string } } }).params.path.product);
      return { data: { items: held, more } };
    }
    return undefined;
  });
  return { sent: answer("PUT", () => ({ data: { added: 1, closed: 0 } })), asked };
}

async function opened() {
  mount.render(screen(<AffectedBuilds product="sonic" vulnerability="OPENPSIRT-2026-1" />));
  await press(mount.host(), "▸ Which builds this affects");
  await settle();
}

describe("correcting which builds a flaw affects", () => {
  it("writes nothing where it is open at more builds than one write names", async () => {
    const many = Array.from({ length: 200 }, (_, i) => ({
      branch_or_tag: `b${i}`,
      variant: "broadcom",
    }));
    const { sent } = serving(many, true);
    await opened();
    expect(mount.host().textContent).toContain("more builds than this screen can set");
    expect(mount.host().textContent).toContain("More than 200 builds carry it here");
    expect(mount.host().querySelectorAll('input[type="checkbox"]')).toHaveLength(0);
    expect(() => button(mount.host(), "Set which builds it affects")).toThrow();
    expect(sent()).toHaveLength(0);
  });

  it("reads the builds of the product it was opened in, as the address names it", async () => {
    const { sent, asked } = serving([{ branch_or_tag: "master", variant: "broadcom" }]);
    mount.render(screen(<AffectedBuilds product="SONiC" vulnerability="OPENPSIRT-2026-1" />));
    await press(mount.host(), "▸ Which builds this affects");
    await settle();
    expect(asked).toEqual(["SONiC"]);
    tick(mount.host(), "v1.0");
    await press(mount.host(), "Set which builds it affects");
    await settle();
    expect((sent()[0]?.[1] as { body: { builds: unknown[] } }).body.builds).toEqual([
      { branch_or_tag: "master", variant: "broadcom" },
      { branch_or_tag: "v1.0", variant: "broadcom" },
    ]);
  });

  it("sends the whole set it holds, with the build added", async () => {
    const { sent } = serving([{ branch_or_tag: "master", variant: "broadcom" }]);
    await opened();
    tick(mount.host(), "v1.0");
    await press(mount.host(), "Set which builds it affects");
    await settle();
    expect(sent()).toHaveLength(1);
    expect((sent()[0]?.[1] as { body: unknown }).body).toEqual({
      builds: [
        { branch_or_tag: "master", variant: "broadcom" },
        { branch_or_tag: "v1.0", variant: "broadcom" },
      ],
    });
    expect(mount.host().textContent).toContain("1 added · 0 closed as never affected.");
  });

  it("asks why a build comes out before it sends the narrower set", async () => {
    const { sent } = serving([
      { branch_or_tag: "master", variant: "broadcom" },
      { branch_or_tag: "v1.0", variant: "broadcom" },
    ]);
    await opened();
    tick(mount.host(), "v1.0");
    expect(button(mount.host(), "Set which builds it affects").disabled).toBe(true);
    change(mount.host().querySelector("#affects-because"), "Cut before the code arrived.");
    await press(mount.host(), "Set which builds it affects");
    await settle();
    expect((sent()[0]?.[1] as { body: unknown }).body).toEqual({
      builds: [{ branch_or_tag: "master", variant: "broadcom" }],
      reason: "Cut before the code arrived.",
    });
  });
});
