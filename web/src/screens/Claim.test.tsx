// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import type { Who } from "../app/session";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Claim } from "./Claim";
import { accept, client, mounted, screen, serve, settle, watchInvalidations } from "../test/mount";

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
