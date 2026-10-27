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

// Two decisions standing on one finding, each with a summary of its own.
const finding = {
  vulnerability: "CVE-2026-1",
  component: "libnl",
  severity: "high",
  occurrences: [],
  standing: [
    { decision_occurrence_id: 11, decision_id: 101, occurrences: 3, state: "proposed" },
    { decision_occurrence_id: 12, decision_id: 102, occurrences: 7, state: "proposed" },
  ],
};

function decision(id: number, decisionId: number) {
  return {
    decision_occurrence: { id, decision_id: decisionId, outcome: "wont-fix", state: "proposed" },
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
    if (path === "/v1/decision-occurrences/{id}") {
      const id = (init as { params: { path: { id: number } } }).params.path.id;
      const answer = decisions[id];
      return answer ? { data: answer } : { status: 500 };
    }
    return { data: { items: [], total: 0 } };
  });
}

function card(decisionId: number): HTMLElement | undefined {
  return Array.from(mount.host().querySelectorAll<HTMLElement>(".card.standing")).find(
    (each) => each.querySelector("h3 .id")?.textContent === `#${decisionId}`,
  );
}

describe("the decisions standing on a finding", () => {
  it("draws each decision with its own summary when an earlier read fails", async () => {
    serving({ 12: decision(12, 102) });
    mount.render(screen(<Finding />, ADDRESS, PATTERN));
    await settle();
    expect(card(101)).toBeUndefined();
    expect(card(102)?.textContent).toContain("7 occurrences here");
    expect(mount.host().textContent).toContain("CVE-2026-1");
  });

  it("draws both decisions, each with its own summary, when both are read", async () => {
    serving({ 11: decision(11, 101), 12: decision(12, 102) });
    mount.render(screen(<Finding />, ADDRESS, PATTERN));
    await settle();
    expect(card(101)?.textContent).toContain("3 occurrences here");
    expect(card(102)?.textContent).toContain("7 occurrences here");
  });
});
