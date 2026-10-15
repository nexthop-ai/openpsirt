// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import type { Who } from "../app/session";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Claim } from "./Claim";
import { accept, client, mounted, screen, serve, settle, watchInvalidations } from "../test/mount";
import { only } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ANA: Who = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [],
  outcomes: [],
};

describe("re-affirming a lapsed claim from its own page", () => {
  it("refreshes every list the re-made claim joins, the proposer's own among them", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: ANA };
      if (path === "/v1/claims/{id}") {
        return {
          data: {
            claim: { id: 4, proposed_by: "ana" },
            place: { product: "sonic", vulnerability: "CVE-2026-1" },
            argument: { outcome: "not-applicable" },
            issues: 1,
            places: 1,
            age_days: 1,
            reaffirmable: true,
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    accept(() => ({ data: { claim_id: 9, waiting: false } }));
    const queries = client();
    mount.render(screen(<Claim who={ANA} />, "/claims/4", "/claims/:id", queries));
    await settle();
    const invalidated = watchInvalidations(queries);
    const box = mount
      .host()
      .querySelector<HTMLTextAreaElement>(
        'textarea[placeholder="The reason it still holds, having checked again"]',
      );
    if (!box) throw new Error("no re-affirm form");
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(
        box,
        "Checked again.",
      );
      box.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const button = Array.from(mount.host().querySelectorAll("button")).find((each) =>
      each.textContent?.startsWith("Re-affirm all"),
    );
    await act(async () => button?.click());
    await settle();
    expect(invalidated()).toEqual(expect.arrayContaining(["claim", "my-claims", "decided"]));
  });
});

describe("the stripe on a claim's page", () => {
  it("draws a proposed claim nothing waits on as in force", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: ANA };
      if (path === "/v1/claims/{id}") {
        return {
          data: {
            claim: { id: 4, proposed_by: "ana" },
            place: { product: "sonic", vulnerability: "CVE-2026-1" },
            argument: { outcome: "not-applicable" },
            happened: "waiting",
            issues: 1,
            places: 1,
            age_days: 1,
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Claim who={ANA} />, "/claims/4", "/claims/:id", client()));
    await settle();
    const card = mount.host().querySelector(".card.standing");
    expect(card?.classList.contains("approved")).toBe(true);
    expect(card?.classList.contains("pending")).toBe(false);
  });
});

describe("the answer a second person gives", () => {
  // The claim waits on somebody who agrees to public findings in sonic.
  function waiting(proposedBy: string, undisclosed = false) {
    return {
      claim: { id: 4, proposed_by: proposedBy },
      place: { product: "sonic", vulnerability: "CVE-2026-1" },
      argument: { outcome: "not-applicable" },
      happened: "waiting",
      undisclosed,
      issues: 1,
      places: 1,
      age_days: 1,
    };
  }

  async function drawn(claim: object, who: Who) {
    serve((path) => {
      if (path === "/v1/session/me") return { data: who };
      if (path === "/v1/claims/{id}") return { data: claim };
      return { data: { items: [], total: 0 } };
    });
    const sent = accept(() => ({ data: {} }));
    mount.render(screen(<Claim who={who} />, "/claims/4", "/claims/:id"));
    await settle();
    return sent;
  }

  const BO: Who = {
    ...ANA,
    identity: "bo",
    name: "Bo",
    reach: [{ product: "sonic", agrees_public: true }] as unknown as Who["reach"],
  };
  const agree = () =>
    Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Agree",
    );

  it("offers the proposer no Agree, whatever they hold", async () => {
    await drawn(waiting("bo"), BO);
    expect(agree()).toBeUndefined();
  });

  it("offers somebody else who may agree an Agree, and sends it for this claim", async () => {
    const sent = await drawn(waiting("ana"), BO);
    await act(async () => agree()?.click());
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/claims/{id}/approval");
    expect(init.params?.path).toEqual({ id: 4 });
  });

  it("offers no Agree on an undisclosed claim to somebody who agrees only to public ones", async () => {
    await drawn(waiting("ana", true), BO);
    expect(agree()).toBeUndefined();
  });
});
