// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it } from "vitest";
import { Published } from "./Published";
import { mounted, screen, serve, settle } from "../../test/mount";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());

const ROUTE = "/v1/advisories/published";

type Asked = { params?: { query?: Record<string, unknown> } };

const text = () => mount.host().textContent ?? "";

async function drawn(items: Record<string, unknown>[]) {
  window.sessionStorage.setItem("openpsirt.scope", JSON.stringify({ product: "sonic" }));
  const spy = serve((path) => (path === ROUTE ? { data: { items } } : undefined));
  mount.render(screen(<Published />, "/analytics/advisories-issued"));
  await settle();
  return (spy.mock.calls as unknown as [string, Asked][])
    .filter(([path]) => path === ROUTE)
    .map(([, init]) => init.params?.query ?? {});
}

describe("the advisories issued", () => {
  it("counts the revisions among what was published, for the product in scope", async () => {
    const asked = await drawn([
      {
        advisory: "OPSA-2026-0001",
        title: "A flaw",
        ordinal: 2,
        issues: 1,
        products: 3,
        issued_at: "2026-03-01T00:00:00Z",
        issued_by: "ana",
        digest: "0123456789abcdef",
        summary: "Corrected the range.",
      },
      { advisory: "OPSA-2026-0002", ordinal: 1, issues: 2, products: 1 },
    ]);
    expect(asked[0]).toMatchObject({ product: "sonic" });
    expect(text()).toContain("2 advisories, 1 of them a revision");
    expect(text()).toContain("1 issue in 3 products");
    expect(text()).toContain("revision 1");
    expect(text()).toContain("0123456789ab");
    const document = mount.host().querySelector("a.id");
    expect(document?.getAttribute("href")).toContain("/v1/advisories/OPSA-2026-0001/document");
  });

  it("says nothing was published in the window", async () => {
    await drawn([]);
    expect(text()).toContain("Nothing has been published in this window.");
  });
});
