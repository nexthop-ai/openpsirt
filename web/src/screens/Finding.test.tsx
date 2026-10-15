// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { belongTo } from "../app/drafts";
import { Finding } from "./Finding";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

beforeEach(() => {
  window.localStorage.clear();
  belongTo("oidc:ana");
});

afterEach(() => vi.restoreAllMocks());

const ADDRESS =
  "/products/sonic/streams/master/variants/broadcom/findings/CVE-2026-1/components/libnl";
const PATTERN =
  "/products/:product/streams/:stream/variants/:variant/findings/:vulnerability/components/:component";

// Two claims standing on one finding, each with a summary of its own.
const finding = {
  vulnerability: "CVE-2026-1",
  component: "libnl",
  severity: "high",
  places: [],
  standing: [
    { decision_id: 11, claim_id: 101, places: 3, state: "proposed" },
    { decision_id: 12, claim_id: 102, places: 7, state: "proposed" },
  ],
};

function claim(id: number, claimId: number) {
  return {
    decision: { id, claim_id: claimId, outcome: "wont-fix", state: "proposed" },
    proposed_by: "bob",
  };
}

function serving(decisions: Record<number, unknown>) {
  serve((path, init) => {
    if (path === "/v1/session/me") {
      return {
        data: {
          identity: "ana",
          name: "Ana",
          admin: false,
          kind: "person",
          reach: [{ product: "sonic", name: "sonic", triages_public: true }],
        },
      };
    }
    if (path.endsWith("/components/{component}")) return { data: finding };
    if (path === "/v1/decisions/{id}") {
      const id = (init as { params: { path: { id: number } } }).params.path.id;
      const answer = decisions[id];
      return answer ? { data: answer } : { status: 500 };
    }
    return { data: { items: [], total: 0 } };
  });
}

function card(claimId: number): HTMLElement | undefined {
  return Array.from(mount.host().querySelectorAll<HTMLElement>(".card.standing")).find(
    (each) => each.querySelector("h3 .id")?.textContent === `#${claimId}`,
  );
}

describe("the claims standing on a finding", () => {
  it("draws each claim with its own summary when an earlier read fails", async () => {
    serving({ 12: claim(12, 102) });
    mount.render(screen(<Finding />, ADDRESS, PATTERN));
    await settle();
    expect(card(101)).toBeUndefined();
    expect(card(102)?.textContent).toContain("7 places here");
    expect(mount.host().textContent).toContain("CVE-2026-1");
  });

  it("draws both claims, each with its own summary, when both are read", async () => {
    serving({ 11: claim(11, 101), 12: claim(12, 102) });
    mount.render(screen(<Finding />, ADDRESS, PATTERN));
    await settle();
    expect(card(101)?.textContent).toContain("3 places here");
    expect(card(102)?.textContent).toContain("7 places here");
  });
});
