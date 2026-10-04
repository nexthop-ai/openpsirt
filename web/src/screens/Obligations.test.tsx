// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Obligations } from "./Obligations";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const record = (id: number, product: string, vulnerability: string) => ({
  id,
  product,
  product_name: product.toUpperCase(),
  vulnerability,
  standing: true,
  known_at: "2026-09-01T00:00:00Z",
  grounds: "Seen in the field.",
  windows: [],
  told: [],
});

function shelf() {
  serve((asked) => {
    if (asked === "/v1/obligations") {
      return {
        data: {
          items: [record(1, "sonic", "CVE-2026-0001"), record(2, "edge", "CVE-2026-0002")],
        },
      };
    }
    if (asked === "/v1/session/me") {
      return { data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] } };
    }
    return { data: { items: [], total: 0 } };
  });
}

describe("the shelf of standing attacks", () => {
  it("narrows to the product the address names, and offers every product back", async () => {
    shelf();
    mount.render(screen(<Obligations />, "/obligations?product=sonic"));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("CVE-2026-0001");
    expect(text).not.toContain("CVE-2026-0002");
    expect(text).toContain("Attacks on SONIC");
    expect(mount.host().querySelector('a[href="/obligations"]')?.textContent).toBe("every product");
  });

  it("lists every product's records where the address names none", async () => {
    shelf();
    mount.render(screen(<Obligations />, "/obligations"));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("CVE-2026-0001");
    expect(text).toContain("CVE-2026-0002");
  });
});
