// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { AffectedBuilds } from "./FindingBuilds";
import { button, change, press, tick } from "../test/controls";
import { answer, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const releases = [
  { branch_or_tag: "master", variant: "broadcom", kind: "branch" },
  { branch_or_tag: "v1.0", variant: "broadcom", kind: "tag" },
  { branch_or_tag: "v2.0", variant: "broadcom", kind: "tag" },
];

// The issue as the server answers it: the rows of the page asked for, and how
// many there are in all. Asked about sonic alone, it answers sonic's rows;
// asked about every product, it counts a thousand more rows elsewhere. A total
// past the rows held is rows the server lost between pages.
function serving(
  held: { branch_or_tag: string; variant: string; component?: string }[],
  total: number,
) {
  serve((path, init) => {
    if (path === "/v1/products/{product}/releases") return { data: { items: releases } };
    if (path === "/v1/issues/{issue}") {
      const asked = (
        init as { params: { query?: { product?: string; limit?: number; offset?: number } } }
      ).params.query;
      const from = asked?.offset ?? 0;
      const items = held
        .slice(from, from + (asked?.limit ?? 200))
        .map((each) => ({ ...each, product: "sonic" }));
      return asked?.product === "sonic"
        ? { data: { items, total } }
        : { data: { items, total: total + 1000 } };
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
    const sent = serving([{ branch_or_tag: "master", variant: "broadcom" }], 6);
    await opened();
    expect(mount.host().textContent).toContain("more builds than this screen can set");
    expect(mount.host().querySelectorAll('input[type="checkbox"]')).toHaveLength(0);
    expect(() => button(mount.host(), "Set which builds it affects")).toThrow();
    expect(sent()).toHaveLength(0);
  });

  it("writes nothing where it is open at more builds than one write names", async () => {
    const many = Array.from({ length: 201 }, (_, i) => ({
      branch_or_tag: `b${i}`,
      variant: "broadcom",
    }));
    const sent = serving(many, many.length);
    await opened();
    expect(mount.host().textContent).toContain("more builds than this screen can set");
    expect(mount.host().textContent).toContain("one change names at most 200");
    expect(mount.host().textContent).not.toContain("writing from what is shown");
    expect(() => button(mount.host(), "Set which builds it affects")).toThrow();
    expect(sent()).toHaveLength(0);
  });

  it("edits a product whose rows run past one page while its builds fit one write", async () => {
    const rows = ["master", "v1.0"].flatMap((branch) =>
      Array.from({ length: 300 }, (_, i) => ({
        branch_or_tag: branch,
        variant: "broadcom",
        component: `module-${i}`,
      })),
    );
    const sent = serving(rows, rows.length);
    await opened();
    expect(mount.host().textContent).not.toContain("more builds than this screen can set");
    tick(mount.host(), "v2.0");
    await press(mount.host(), "Set which builds it affects");
    await settle();
    expect((sent()[0]?.[1] as { body: { builds: unknown[] } }).body.builds).toHaveLength(3);
  });

  it("edits one product's builds however many rows other products hold", async () => {
    serving([{ branch_or_tag: "master", variant: "broadcom" }], 1);
    await opened();
    expect(mount.host().textContent).not.toContain("more builds than this screen can set");
    expect(mount.host().querySelectorAll('input[type="checkbox"]')).toHaveLength(3);
  });

  it("sends the whole set it holds, with the build added", async () => {
    const sent = serving([{ branch_or_tag: "master", variant: "broadcom" }], 1);
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
    const sent = serving(
      [
        { branch_or_tag: "master", variant: "broadcom" },
        { branch_or_tag: "v1.0", variant: "broadcom" },
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
      builds: [{ branch_or_tag: "master", variant: "broadcom" }],
      reason: "Cut before the code arrived.",
    });
  });
});
