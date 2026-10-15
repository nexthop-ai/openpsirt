// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Release } from "./Release";
import { screen, serve, settle, mounted } from "../test/mount";
import type { Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("a release", () => {
  it("says its variants could not be read rather than that nothing was filed", async () => {
    serve((path) =>
      path === "/v1/products/{product}/streams"
        ? { data: { items: [{ name: "v1.2" }], total: 1 } }
        : { status: 503 },
    );
    mount.render(screen(<Release product="sonic" stream="v1.2" />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("could not be read");
    expect(text).not.toContain("Nothing has been filed against it");
    expect(text).not.toContain("open in all");
  });

  it("opens a retired tag and says it is retired", async () => {
    // The list of lines answers a retired one only when asked to include
    // them, as the server does.
    serve((path, init) => {
      if (path === "/v1/products/{product}/streams") {
        const retired = (init as Init).params?.query?.retired === true;
        const items = [
          { name: "202411.1", kind: "tag" },
          { name: "202305.9", kind: "tag", retired: true },
        ];
        return { data: { items: items.filter((each) => retired || !each.retired) } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Release product="sonic" stream="202305.9" />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).not.toContain("No such release");
    expect(mount.host().querySelector("h2")?.textContent).toBe("202305.9");
    expect(text).toContain("Retired");
  });
});
