// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Who } from "../app/session";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Inventories } from "./Inventories";
import { InventoryCompare } from "./InventoryCompare";
import { Exploited } from "./Exploited";
import { GrantGrid } from "./GrantGrid";
import { Home } from "./Home";
import { Revisions, Standing } from "./FindingClaim";
import { Products } from "./Products";
import { Decide } from "../ui/Decide";
import { PUBLISHED } from "../test/outcomes";
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
    if (asked === path || (path.startsWith("*") && asked.endsWith(path.slice(1)))) {
      return { status: 503 };
    }
    if (asked === "/v1/session/me") {
      return {
        data: {
          identity: "ana",
          name: "Ana",
          admin: true,
          kind: "person",
          reach: [],
          outcomes: PUBLISHED,
        },
      };
    }
    return { data: { items: [], total: 0 } };
  });
}

const ANA: Who = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [],
  outcomes: [],
};

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

  it("says the exploited figure could not be read rather than drawing no tile", async () => {
    failing("/v1/obligations");
    mount.render(screen(<Home who={ANA} />));
    await settle();
    const tile = Array.from(mount.host().querySelectorAll(".kpi")).find((each) =>
      each.textContent?.includes("Exploited here"),
    );
    expect(tile).toBeDefined();
    expect(tile?.querySelector(".count-failed")).not.toBeNull();
  });

  it("says how long a build may go quiet could not be read rather than a week", async () => {
    failing("/v1/scanning");
    mount.render(screen(<Home who={ANA} />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("Quiet after");
    expect(text).not.toContain("7 days");
    expect(mount.host().querySelector(".count-failed")).not.toBeNull();
  });

  it("says the release trend could not be read rather than drawing the calendar", async () => {
    failing("/v1/trend/releases");
    mount.render(screen(<Home who={ANA} />, "/products/sonic/streams/master/variants/x", BUILD));
    await settle();
    expect(mount.host().textContent).toContain("The release trend could not be read.");
  });

  it("says no build is flagged quiet where the setting could not be read", async () => {
    failing("/v1/scanning");
    mount.render(screen(<Products who={{ ...ANA, admin: true }} />));
    await settle();
    expect(mount.host().textContent).toContain(
      "How long a build may go unscanned could not be read, so nothing is flagged.",
    );
  });

  it("says other builds could not be read rather than that none match", async () => {
    failing("*/reach");
    mount.render(
      screen(
        <Decide
          at={{
            product: "sonic",
            stream: "master",
            variant: "broadcom",
            vulnerability: "CVE-2026-1",
            component: "openssl",
            version: "3.0.2",
          }}
          places={[{ place: "p1", component: "openssl" }]}
          onDone={() => undefined}
        />,
      ),
    );
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("Other builds with this component could not be read.");
    expect(text).not.toContain("other builds match");
  });

  it("says who approved a decision is unknown rather than that nobody had to", async () => {
    failing("/v1/claims/{id}/approvals");
    mount.render(
      screen(
        <Standing
          claim={{
            decision: {
              claim_id: 4,
              state: "approved",
              needs_approval: false,
              outcome: "not-applicable",
              reasoning: "Unreachable.",
            },
            age_days: 1,
            place: { place: "p1", product: "sonic", vulnerability: "CVE-2026-1" },
            proposed_at: "2026-10-01T00:00:00Z",
            proposed_by: "bo",
            reasoning: "Unreachable.",
          }}
          places={[]}
          mine={false}
          mayApprove={false}
          onRevised={() => undefined}
          about={{ product: "sonic", vulnerability: "CVE-2026-1" }}
        />,
      ),
    );
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("who approved it could not be read");
    expect(text).not.toContain("needed nobody");
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
