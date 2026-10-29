// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { SuppressionRules } from "./SuppressionRules";
import { accept, mounted, screen, serve, settle } from "../test/mount";
import { change, labeled, press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const RULES = [
  {
    id: 1,
    rule: "cppcheck/knownConditionTrueFalse",
    reason: "false_positive",
    reasoning: "x",
    covering: 12,
    proposed_at: "2026-10-01T00:00:00Z",
    proposed_by: 2,
    state: "proposed",
  },
  {
    id: 2,
    rule: "cppcheck/uninitvar",
    prefix: "third_party",
    reason: "wont_fix",
    reasoning: "y",
    covering: 40,
    approved_covering: 10,
    proposed_at: "2026-09-01T00:00:00Z",
    proposed_by: 2,
    state: "outgrown",
  },
  {
    id: 3,
    rule: "clang/deadcode.DeadStores",
    reason: "wont_fix",
    reasoning: "z",
    covering: 3,
    proposed_at: "2026-10-02T00:00:00Z",
    proposed_by: 1,
    yours: true,
    state: "proposed",
  },
];

async function drawn(may: {
  triages_security_testing?: boolean;
  agrees_security_testing?: boolean;
}) {
  serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          kind: "person",
          reach: [{ product: "sonic", reads_security_testing: true, ...may }],
          outcomes: [],
        },
      };
    if (path === "/v1/products/{product}/suppression-rules") return { data: { items: RULES } };
    return undefined;
  });
  mount.render(
    screen(
      <SuppressionRules />,
      "/products/sonic/suppression-rules",
      "/products/:product/suppression-rules",
    ),
  );
  await settle();
}

const text = () => mount.host().textContent ?? "";
const buttons = (label: string) =>
  [...mount.host().querySelectorAll("button")].filter((b) => b.textContent?.trim() === label);

describe("the suppression rules", () => {
  it("says what each covers and where it stands", async () => {
    await drawn({});
    expect(text()).toContain("cppcheck/knownConditionTrueFalse");
    expect(text()).toContain("40 · 10 when approved");
    expect(text()).toContain("Outgrown");
  });

  it("offers approval to an approver, for a rule waiting or outgrown that is not theirs", async () => {
    await drawn({ agrees_security_testing: true });
    expect(buttons("Approve")).toHaveLength(2);
    expect(buttons("Retire")).toHaveLength(0);
    const sent = accept(() => ({ data: RULES[0] }));
    await press(mount.host(), "Approve");
    await settle();
    expect(sent()[0]?.[0]).toBe("/v1/products/{product}/suppression-rules/{id}/approval");
  });

  it("offers nothing that writes to somebody who only reads", async () => {
    await drawn({});
    expect(buttons("Approve")).toHaveLength(0);
    expect(buttons("Propose")).toHaveLength(0);
    expect(mount.host().querySelector("textarea")).toBeNull();
  });

  it("proposes a rule naming a path alone", async () => {
    await drawn({ triages_security_testing: true });
    const sent = accept(() => ({ status: 201, data: RULES[1] }));
    change(labeled(mount.host(), "Path"), "vendor");
    change(mount.host().querySelector<HTMLSelectElement>("#suppression-rule-reason"), "wont_fix");
    change(mount.host().querySelectorAll<HTMLTextAreaElement>("textarea")[0] ?? null, "not ours");
    await press(mount.host(), "Propose");
    await settle();
    expect((sent()[0]?.[1] as { body: unknown }).body).toEqual({
      prefix: "vendor",
      reason: "wont_fix",
      reasoning: "not ours",
    });
  });
});
