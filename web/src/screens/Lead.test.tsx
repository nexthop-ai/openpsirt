// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Lead } from "./Lead";
import { accept, mounted, screen, serve, settle } from "../test/mount";
import { change, pick, press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const AT = "/products/sonic/streams/master/variants/broadcom/leads/abc";
const PATTERN = "/products/:product/streams/:stream/variants/:variant/leads/:place";

const EVIDENCE = {
  rule: "clang/unix.Malloc",
  at: { path: "src/a.c", start_line: 7, message: "p is leaked", link: "javascript:alert(1)" },
  steps: [
    {
      path: "src/a.c",
      start_line: 3,
      message: "allocated here",
      link: "https://git.example/a.c#L3",
    },
  ],
  related: [],
  kin: [
    { place: "def", rule: "cppcheck/memleak", path: "src/a.c", line: 8, same: true },
    { place: "ghi", rule: "codeql/cpp/leak", path: "src/a.c", line: 15, same: false },
  ],
  last_seen: "2026-10-01T00:00:00Z",
  open: true,
  state: "open",
};

async function drawn(triages: boolean, evidence: object = EVIDENCE) {
  serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          kind: "person",
          reach: [{ product: "sonic", reads_internal: true, triages_internal: triages }],
          outcomes: [],
        },
      };
    if (path === "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}")
      return { data: evidence };
    return undefined;
  });
  mount.render(screen(<Lead />, AT, PATTERN));
  await settle();
}

const text = () => mount.host().textContent ?? "";

describe("a lead", () => {
  it("names its rule, the path the analyzer took, and the leads that are the same flaw", async () => {
    await drawn(false);
    expect(text()).toContain("clang/unix.Malloc");
    expect(text()).toContain("allocated here");
    expect(text()).toContain("Same flaw");
    expect(text()).toContain("cppcheck/memleak");
    expect(text()).toContain("Possibly the same flaw");
  });

  it("links a step at an address a browser may open, and not one it may not", async () => {
    await drawn(false);
    const hrefs = [...mount.host().querySelectorAll("a")].map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("https://git.example/a.c#L3");
    expect(hrefs.some((h) => h?.startsWith("javascript:"))).toBe(false);
  });

  it("offers no judgment to somebody who only reads it", async () => {
    await drawn(false);
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(0);
  });

  it("offers no way into the queue to somebody who only reads it", async () => {
    await drawn(false, { ...EVIDENCE, state: "baseline" });
    expect(text()).not.toContain("Add to the queue");
  });

  it("names the claim standing at it in place of the form", async () => {
    await drawn(true, {
      ...EVIDENCE,
      decision: {
        claim_id: 4,
        outcome: "dismissed",
        reason: "false_positive",
        reasoning: "",
        needs_approval: true,
        state: "proposed",
      },
    });
    expect(text()).toContain("Claim 4");
    expect(text()).toContain("Waiting for approval");
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(0);
  });

  it("sends a dismissal with its reason", async () => {
    await drawn(true);
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(3);
    const sent = accept(() => ({ status: 201, data: { outcome: "dismissed", reasoning: "x" } }));
    pick(mount.host(), "Dismissed");
    change(mount.host().querySelector<HTMLSelectElement>("#lead-reason"), "false_positive");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "checked a line above");
    await press(mount.host(), "Propose");
    await settle();
    const [path, init] = sent()[0] ?? [];
    expect(path).toBe(
      "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/decision",
    );
    expect((init as { body: unknown }).body).toEqual({
      outcome: "dismissed",
      reason: "false_positive",
      reasoning: "checked a line above",
    });
  });

  it("offers to take a lead out of the baseline", async () => {
    await drawn(true, { ...EVIDENCE, state: "baseline" });
    expect(text()).toContain("Add to the queue");
  });

  it("is kept as it stands once every release it was seen in is past its end of life", async () => {
    await drawn(true, { ...EVIDENCE, past_end_of_life: true });
    expect(text()).toContain("Past end of life");
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(0);
  });

  it("offers no way into the queue once it is past its end of life", async () => {
    await drawn(true, { ...EVIDENCE, state: "baseline", past_end_of_life: true });
    expect(text()).not.toContain("Add to the queue");
  });
});
