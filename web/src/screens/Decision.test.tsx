// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import type { Who } from "../app/session";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Decision } from "./Decision";
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

describe("re-affirming a lapsed decision from its own page", () => {
  it("refreshes every list the re-made decision joins, the proposer's own among them", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: ANA };
      if (path === "/v1/decisions/{id}") {
        return {
          data: {
            decision: { id: 4, proposed_by: "ana" },
            occurrence: { product: "sonic", vulnerability: "CVE-2026-1" },
            argument: { outcome: "not-applicable" },
            issues: 1,
            occurrences: 1,
            age_days: 1,
            reaffirmable: true,
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    accept(() => ({ data: { decision_id: 9, waiting: false } }));
    const queries = client();
    mount.render(screen(<Decision who={ANA} />, "/decisions/4", "/decisions/:id", queries));
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
    expect(invalidated()).toEqual(expect.arrayContaining(["decision", "my-decisions", "decided"]));
  });
});

describe("the stripe on a decision's page", () => {
  it("draws a proposed decision nothing waits on as in force", async () => {
    serve((path) => {
      if (path === "/v1/session/me") return { data: ANA };
      if (path === "/v1/decisions/{id}") {
        return {
          data: {
            decision: { id: 4, proposed_by: "ana" },
            occurrence: { product: "sonic", vulnerability: "CVE-2026-1" },
            argument: { outcome: "not-applicable" },
            happened: "waiting",
            issues: 1,
            occurrences: 1,
            age_days: 1,
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Decision who={ANA} />, "/decisions/4", "/decisions/:id", client()));
    await settle();
    const card = mount.host().querySelector(".card.standing");
    expect(card?.classList.contains("approved")).toBe(true);
    expect(card?.classList.contains("pending")).toBe(false);
  });
});

describe("the answer a second person gives", () => {
  // The decision waits on somebody who agrees to public findings in sonic.
  function waiting(proposedBy: string, undisclosed = false, internal = false) {
    return {
      decision: { id: 4, proposed_by: proposedBy },
      occurrence: { product: "sonic", vulnerability: "CVE-2026-1" },
      argument: { outcome: "not-applicable" },
      happened: "waiting",
      undisclosed,
      internal,
      issues: 1,
      occurrences: 1,
      age_days: 1,
    };
  }

  async function drawn(decision: object, who: Who) {
    serve((path) => {
      if (path === "/v1/session/me") return { data: who };
      if (path === "/v1/decisions/{id}") return { data: decision };
      return { data: { items: [], total: 0 } };
    });
    const sent = accept(() => ({ data: {} }));
    mount.render(screen(<Decision who={who} />, "/decisions/4", "/decisions/:id"));
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

  it("offers somebody else who may agree an Agree, and sends it for this decision", async () => {
    const sent = await drawn(waiting("ana"), BO);
    await act(async () => agree()?.click());
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/decisions/{id}/approval");
    expect(init.params?.path).toEqual({ id: 4 });
  });

  it("offers no Agree on an undisclosed decision to somebody who agrees only to public ones", async () => {
    await drawn(waiting("ana", true), BO);
    expect(agree()).toBeUndefined();
  });

  // A lead decision is internal, and its second person holds the approver
  // capability: a private triager is refused it, and an internal approver
  // who triages nothing undisclosed is not.
  it("offers no Agree on a lead decision to a triager of undisclosed work", async () => {
    const privateTriager: Who = {
      ...BO,
      reach: [{ product: "sonic", agrees_private: true }] as unknown as Who["reach"],
    };
    await drawn(waiting("ana", true, true), privateTriager);
    expect(agree()).toBeUndefined();
  });

  it("offers Agree on a lead decision to an approver of internal work", async () => {
    const reviewer: Who = {
      ...BO,
      reach: [{ product: "sonic", agrees_internal: true }] as unknown as Who["reach"],
    };
    await drawn(waiting("ana", true, true), reviewer);
    expect(agree()).toBeDefined();
  });
});

describe("a decision about internal material read by somebody who may not argue it", () => {
  async function drawn(may: Record<string, boolean>) {
    const reader: Who = {
      ...ANA,
      identity: "bo",
      reach: [{ product: "sonic", ...may }] as unknown as Who["reach"],
    };
    serve((path) => {
      if (path === "/v1/session/me") return { data: reader };
      if (path === "/v1/decisions/{id}") {
        return {
          data: {
            decision: { id: 4, proposed_by: "ana" },
            occurrence: { product: "sonic", vulnerability: "clang-tidy/leak" },
            argument: { outcome: "confirmed" },
            happened: "waiting",
            internal: true,
            issues: 1,
            occurrences: 1,
            age_days: 1,
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Decision who={reader} />, "/decisions/4", "/decisions/:id", client()));
    await settle();
    const text = mount.host().textContent ?? "";
    const buttons = Array.from(mount.host().querySelectorAll("button")).map((b) => b.textContent);
    return {
      comments: text.includes("Add a comment"),
      links: buttons.includes("Link it"),
      revises: buttons.includes("Revise reasoning") && buttons.includes("Withdraw"),
    };
  }

  it("offers no comment box, link, revision or withdrawal to somebody who only reads it", async () => {
    expect(await drawn({ reads_private: true })).toEqual({
      comments: false,
      links: false,
      revises: false,
    });
  });

  it("offers a comment box to an approver and every write to a triager", async () => {
    expect(await drawn({ agrees_internal: true })).toEqual({
      comments: true,
      links: false,
      revises: false,
    });
    expect(await drawn({ triages_internal: true })).toEqual({
      comments: true,
      links: true,
      revises: true,
    });
  });
});
