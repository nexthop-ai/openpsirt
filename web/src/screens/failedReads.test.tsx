// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Inventories } from "./Inventories";
import { InventoryCompare } from "./InventoryCompare";
import { Exploited } from "./Exploited";
import { GrantGrid } from "./GrantGrid";
import { Home } from "./Home";
import { Revisions } from "./FindingClaim";
import { Notices } from "../ui/Notices";
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
      screen(
        <Inventories />,
        "/products/sonic/streams/master/variants/x/inventories",
        `${BUILD}/inventories`,
      ),
    );
    await settle();
    expect(mount.host().textContent).toContain("Which builds have gone quiet could not be read.");
  });

  it("says the windows could not be read rather than that none are declared", async () => {
    failing("/v1/obligation-windows");
    mount.render(screen(<Exploited />));
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

  it("draws no severity ring over a trend that could not be read", async () => {
    failing("/v1/trend");
    mount.render(
      screen(
        <Home
          who={{
            identity: "ana",
            name: "Ana",
            admin: false,
            kind: "person",
            reach: [],
            outcomes: [],
          }}
        />,
      ),
    );
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("The trend could not be read.");
    expect(text).not.toContain("Nothing is open.");
    expect(text).not.toContain("Not enough history yet.");
  });

  it("says the products could not be read rather than that none are declared", async () => {
    failing("/v1/products");
    mount.render(
      screen(
        <GrantGrid
          holds={[]}
          busy={false}
          onGrant={() => undefined}
          onWithdraw={() => undefined}
          onGrantEverywhere={() => undefined}
          onWithdrawEverywhere={() => undefined}
        />,
      ),
    );
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("The products could not be read.");
    expect(text).not.toContain("No products declared yet.");
  });

  it("says the notices could not be read rather than that nothing is waiting", async () => {
    failing("/v1/notifications");
    mount.render(screen(<Notices />));
    await settle();
    const bell = mount.host().querySelector<HTMLButtonElement>("button.bell");
    expect(bell?.getAttribute("aria-label")).toBe("Notices could not be read");
    bell?.click();
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("Notices could not be read.");
    expect(text).not.toContain("Nothing is waiting on you.");
  });

  it("says a claim's revisions could not be read rather than drawing none", async () => {
    failing("/v1/claims/{id}/revisions");
    mount.render(screen(<Revisions claimId={4} />));
    await settle();
    expect(mount.host().textContent).toContain("The revision history could not be read.");
  });

  it("says who approved a revision is unknown rather than that nobody did", async () => {
    serve((asked) => {
      if (asked === "/v1/claims/{id}/approvals") return { status: 503 };
      if (asked === "/v1/claims/{id}/revisions") {
        return { data: { items: [{ id: 1, ordinal: 1, body: "Unreachable." }] } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Revisions claimId={4} />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("Approvals could not be read");
    expect(text).not.toContain("Never approved");
  });
});
