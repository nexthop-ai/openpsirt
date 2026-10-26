// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Lead } from "./Lead";
import { accept, answer, mounted, screen, serve, settle } from "../test/mount";
import { change, pick, press, type Init } from "../test/controls";

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

async function drawn(triages: boolean, evidence: object = EVIDENCE, hides = false) {
  const spy = serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          kind: "person",
          reach: [
            { product: "sonic", reads_internal: true, triages_internal: triages, may_hide: hides },
          ],
          outcomes: [],
        },
      };
    if (path === "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}")
      return { data: evidence };
    if (path === "/v1/products/{product}/holders")
      return { data: { items: [{ kind: "team", identity: "kernel", name: "Kernel" }] } };
    return undefined;
  });
  mount.render(screen(<Lead />, AT, PATTERN));
  await settle();
  // The visibility each search for a holder asked about.
  return () =>
    (spy.mock.calls as unknown as [string, Init][])
      .filter(([path]) => path === "/v1/products/{product}/holders")
      .map(([, init]) => (init.params?.query as { visibility?: string }).visibility);
}

// Opens the holder picker, as somebody clicking into it does.
async function holderBox() {
  const box = mount.host().querySelector<HTMLInputElement>('input[role="combobox"]');
  if (!box) throw new Error("no holder box");
  box.focus();
  await settle();
  return box;
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

  it("closes a lead nobody sees any more as fixed in the build of the run that did not see it", async () => {
    await drawn(true, { ...EVIDENCE, state: "not-reproduced", not_seen_run: 9 });
    const sent = accept(() => ({ data: { at: "2026-10-02T00:00:00Z" } }));
    const fields = mount.host().querySelectorAll("textarea");
    change(fields[fields.length - 1] ?? null, "the bounds check landed");
    await press(mount.host(), "Close as fixed");
    await settle();
    const fixed = sent().find((call) => String(call[0]).endsWith("/fixed"));
    expect(fixed?.[1]).toMatchObject({ body: { because: "the bounds check landed", fixed_in: 9 } });
  });

  it("names the build a lead was stated fixed in", async () => {
    await drawn(true, {
      ...EVIDENCE,
      open: false,
      state: "fixed",
      fixed_in: { run: 9, built: "2026-10-02T00:00:00Z", commit: "0123456789abcdef" },
    });
    expect(mount.host().textContent).toContain("0123456789ab");
  });

  it("offers no judgment to somebody who only reads it", async () => {
    await drawn(false);
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(0);
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

  it("is kept as it stands once every release it was seen in is past its end of life", async () => {
    await drawn(true, { ...EVIDENCE, past_end_of_life: true });
    expect(text()).toContain("Past end of life");
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(0);
  });

  it("says it is in third-party code where the run declared it so", async () => {
    await drawn(true, { ...EVIDENCE, third_party: true });
    expect(text()).toContain("Third-party");
  });

  it("says nothing about third-party code where the run declared none", async () => {
    await drawn(true, EVIDENCE);
    expect(text()).not.toContain("Third-party");
  });

  it("gives it to a team, across the product, from among readers of internal work", async () => {
    const searched = await drawn(true);
    const sent = answer("PUT", () => ({ status: 204 }));
    await holderBox();
    await press(mount.host(), "Kernel team");
    await settle();
    expect(searched()[0]).toBe("internal");
    const [path, init] = sent()[0] ?? [];
    expect(path).toBe(
      "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/assignment",
    );
    expect((init as { body: unknown }).body).toEqual({ team: "kernel" });
  });

  it("offers no holder once it is handed off and kept", async () => {
    await drawn(true, { ...EVIDENCE, state: "handed-off", handoff: { moved: false } }, true);
    expect(mount.host().querySelector('input[role="combobox"]')).toBeNull();
  });

  it("offers no holder once it is handed off and moved into its case", async () => {
    await drawn(true, { ...EVIDENCE, state: "handed-off", handoff: { moved: true } }, true);
    expect(mount.host().querySelector('input[role="combobox"]')).toBeNull();
  });

  it("names who holds it to somebody who only reads it", async () => {
    await drawn(false, { ...EVIDENCE, assigned_to: "bo", assigned_to_name: "Bo" });
    expect(text()).toContain("Assigned to Bo");
    expect(mount.host().querySelector('input[role="combobox"]')).toBeNull();
  });

  it("offers no holder once it is past its end of life", async () => {
    await drawn(true, { ...EVIDENCE, past_end_of_life: true });
    expect(mount.host().querySelector('input[role="combobox"]')).toBeNull();
  });
});
