// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { useFindingsViews } from "./findingsQueries";
import { listQuery, withinVariant } from "./list";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// What each read asked: the path, and the page it asked for.
function asking() {
  const asked: { path: string; limit?: number }[] = [];
  serve((path, init) => {
    const query = (init as { params?: { query?: { limit?: number } } }).params?.query;
    asked.push({ path, limit: query?.limit });
    return { data: { items: [], total: 0 } };
  });
  return asked;
}

function Views({ spanning, view }: { spanning: boolean; view: string }) {
  useFindingsViews({
    product: spanning ? "" : "sonic",
    stream: "",
    variant: "",
    spanning,
    query: withinVariant(listQuery(new URLSearchParams("page=50")), false),
    selection: {},
    view,
  });
  return null;
}

describe("the findings list's reads", () => {
  it("reads the rows by issue and counts the other two views with a page of one", async () => {
    const asked = asking();
    mount.render(screen(<Views spanning={false} view="issues" />));
    await settle();
    expect(asked).toContainEqual({ path: "/v1/products/{product}/findings", limit: 50 });
    expect(asked).toContainEqual({ path: "/v1/products/{product}/findings/components", limit: 1 });
    expect(asked).toContainEqual({ path: "/v1/products/{product}/fix-bundles", limit: 1 });
    expect(asked).toHaveLength(3);
  });

  it("counts the rows by issue with a page of one where another view is drawn", async () => {
    const asked = asking();
    mount.render(screen(<Views spanning={false} view="components" />));
    await settle();
    expect(asked).toContainEqual({ path: "/v1/products/{product}/findings", limit: 1 });
    expect(asked).not.toContainEqual({ path: "/v1/products/{product}/findings", limit: 50 });
  });

  it("reads across products from the list that spans them, and counts no other view", async () => {
    const asked = asking();
    mount.render(screen(<Views spanning view="issues" />));
    await settle();
    expect(asked).toEqual([{ path: "/v1/findings", limit: 50 }]);
  });
});
