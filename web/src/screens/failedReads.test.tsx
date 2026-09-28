// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Inventories } from "./Inventories";
import { InventoryCompare } from "./InventoryCompare";
import { Obligations } from "./Obligations";
import { screen, serve, settle, mounted } from "../test/mount";

// A secondary read that fails is said, on the screens that read one beside
// their main list. Drawn as its empty answer, a failure states something
// nobody computed.
const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const BUILD = "/products/:product/streams/:stream/variants/:variant";

function failing(path: string) {
  serve((asked) => {
    if (asked === path) return { status: 503 };
    if (asked === "/v1/session/me") {
      return { data: { identity: "ana", name: "Ana", admin: true, kind: "person", reach: [] } };
    }
    return { data: { items: [], total: 0 } };
  });
}

describe("a secondary read that fails", () => {
  it("says which builds went quiet could not be read", async () => {
    failing("/v1/scanning");
    mount.render(
      screen(<Inventories />, "/products/sonic/streams/master/variants/x/scans", `${BUILD}/scans`),
    );
    await settle();
    expect(mount.host().textContent).toContain("Which builds have gone quiet could not be read.");
  });

  it("says the windows could not be read rather than that none are declared", async () => {
    failing("/v1/obligation-windows");
    mount.render(screen(<Obligations />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("The windows could not be read.");
    expect(text).not.toContain("None declared.");
  });

  it("says the builds to compare could not be read", async () => {
    failing("/v1/products/{product}/streams");
    mount.render(
      screen(
        <InventoryCompare />,
        "/products/sonic/comparison/inventory",
        "/products/:product/comparison/inventory",
      ),
    );
    await settle();
    expect(mount.host().textContent).toContain("The builds to compare could not be read.");
  });
});
