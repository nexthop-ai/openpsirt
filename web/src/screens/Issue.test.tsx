// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Issue } from "./Issue";
import { mounted, screen, serve, settle, type Answer } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

async function drawn(issue: Answer) {
  serve((path) => {
    if (path === "/v1/issues/{issue}") return issue;
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<Issue />, "/issues/CVE-2026-1", "/issues/:issue"));
  await settle();
}

const ROWS = [
  {
    product: "sonic",
    product_name: "SONiC",
    branch_or_tag: "master",
    variant: "arm",
    component: "zlib",
    version: "1.2",
    occurrences: 3,
    state: "agreed",
    due: "2026-02-01",
    fixed_in: "1.3",
  },
  {
    product: "sonic",
    branch_or_tag: "202411",
    variant: "arm",
    component: "zlib",
    version: "1.1",
    occurrences: 1,
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
    expect(link?.getAttribute("href")).toContain(
      "/products/sonic/branches-and-tags/master/variants/arm",
    );
  });

  it("says when the issue was published", async () => {
    await drawn({
      data: {
        vulnerability: "CVE-2026-1",
        products: 0,
        total: 0,
        items: [],
        dates: "stated",
        published: "2026-03-04T00:00:00Z",
        modified: "2026-05-06T00:00:00Z",
      },
    });
    expect(text()).toContain("Published");
    expect(text()).toContain("updated");
  });

  it("says nobody knows when the issue was published", async () => {
    await drawn({
      data: { vulnerability: "CVE-2026-1", products: 0, total: 0, items: [], dates: "unknown" },
    });
    expect(text()).toContain("Publication date unknown");
  });

  it("says OSV has not been asked yet", async () => {
    await drawn({
      data: { vulnerability: "CVE-2026-1", products: 0, total: 0, items: [], dates: "unasked" },
    });
    expect(text()).toContain("Publication date not asked yet");
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
