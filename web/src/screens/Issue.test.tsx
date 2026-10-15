// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Issue } from "./Issue";
import { mounted, screen, serve, settle, type Answer } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

async function drawn(issue: Answer) {
  serve((path) => {
    if (path === "/v1/issues/{vulnerability}") return issue;
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<Issue />, "/issues/CVE-2026-1", "/issues/:vulnerability"));
  await settle();
}

const ROWS = [
  {
    product: "sonic",
    product_name: "SONiC",
    stream: "master",
    variant: "arm",
    component: "zlib",
    version: "1.2",
    places: 3,
    state: "agreed",
    due: "2026-02-01",
    fixed_in: "1.3",
  },
  {
    product: "sonic",
    stream: "202411",
    variant: "arm",
    component: "zlib",
    version: "1.1",
    places: 1,
    undisclosed: true,
  },
];

const text = () => mount.host().textContent ?? "";

describe("one issue, everywhere it sits", () => {
  it("lists one row per build and component, each opening its finding", async () => {
    await drawn({
      data: {
        vulnerability: "CVE-2026-1",
        severity: "high",
        products: 1,
        total: 3,
        aliases: ["GHSA-aaaa-bbbb-cccc"],
        merged: [{ vulnerability: "GHSA-dddd-eeee-ffff", merged_at: "2026-01-01T00:00:00Z" }],
        description: "<b>not markup</b>",
        items: ROWS,
      },
    });
    expect(mount.host().querySelectorAll("tbody tr")).toHaveLength(2);
    expect(text()).toContain("fixed in 1.3");
    expect(text()).toContain("undisclosed");
    expect(text()).toContain("Also known as GHSA-aaaa-bbbb-cccc");
    expect(text()).toContain("Merged from GHSA-dddd-eeee-ffff");
    expect(text()).toContain("Showing 2 of 3.");
    // What a scan said is shown as written and never rendered.
    expect(text()).toContain("<b>not markup</b>");
    const link = mount.host().querySelector("tbody a.id");
    expect(link?.getAttribute("href")).toContain("/products/sonic/streams/master/variants/arm");
  });

  it("says nothing carries it rather than drawing an empty table", async () => {
    await drawn({ data: { vulnerability: "CVE-2026-1", products: 0, total: 0, items: [] } });
    expect(text()).toContain("Nothing carries it.");
  });

  it("names the issue it could not read", async () => {
    await drawn({ status: 503 });
    expect(text()).toContain("CVE-2026-1");
    expect(text()).toContain("This issue could not be read.");
  });
});
