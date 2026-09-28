// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Release } from "./Release";
import { screen, serve, settle, mounted } from "../test/mount";

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
});
