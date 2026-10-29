// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { CodeFinding } from "./CodeFinding";
import { accept, answer, mounted, screen, serve, settle } from "../test/mount";
import { change, pick, press, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const AT = "/products/sonic/branches-and-tags/master/variants/broadcom/code-findings/abc";
const PATTERN =
  "/products/:product/branches-and-tags/:branch_or_tag/variants/:variant/code-findings/:occurrence";

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
    { occurrence: "def", rule: "cppcheck/memleak", path: "src/a.c", line: 8, same: true },
    { occurrence: "ghi", rule: "codeql/cpp/leak", path: "src/a.c", line: 15, same: false },
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
            {
              product: "sonic",
              reads_security_testing: true,
              triages_security_testing: triages,
              may_hide: hides,
            },
          ],
          outcomes: [],
        },
      };
    if (
      path ===
      "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}"
    )
      return { data: evidence };
    if (path === "/v1/products/{product}/holders")
      return { data: { items: [{ kind: "team", identity: "kernel", name: "Kernel" }] } };
    return undefined;
  });
  mount.render(screen(<CodeFinding />, AT, PATTERN));
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

describe("a code finding", () => {
  it("names its rule, the path the analyzer took, and the code findings that also found the flaw", async () => {
    await drawn(false);
    expect(text()).toContain("clang/unix.Malloc");
    expect(text()).toContain("allocated here");
    expect(text()).toContain("Also found by");
    expect(text()).toContain("cppcheck/memleak");
    expect(text()).toContain("Possibly also found by");
  });

  it("links the component it is placed on, at the build it is read on", async () => {
    await drawn(false, { ...EVIDENCE, component: "frr", version: "10.2" });
    const link = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "frr 10.2",
    );
    expect(link?.getAttribute("href")).toBe(
      "/products/sonic/components/frr?branch_or_tag=master&variant=broadcom",
    );
  });

  it("says a code finding in no component's repository is on the whole build", async () => {
    await drawn(false, { ...EVIDENCE, component: "sonic", on_build: true });
    expect(text()).toContain("in the whole build");
    const links = Array.from(mount.host().querySelectorAll("a"), (a) => a.getAttribute("href"));
    expect(links.filter((to) => to?.includes("/components/"))).toEqual([]);
  });

  it("links a step at an address a browser may open, and not one it may not", async () => {
    await drawn(false);
    const hrefs = [...mount.host().querySelectorAll("a")].map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("https://git.example/a.c#L3");
    expect(hrefs.some((h) => h?.startsWith("javascript:"))).toBe(false);
  });

  it("closes a code finding nobody sees any more as fixed in the build of the run that did not see it", async () => {
    await drawn(true, { ...EVIDENCE, state: "no-longer-detected", not_seen_run: 9 });
    const sent = accept(() => ({ data: { at: "2026-10-02T00:00:00Z" } }));
    const fields = mount.host().querySelectorAll("textarea");
    change(fields[fields.length - 1] ?? null, "the bounds check landed");
    await press(mount.host(), "Close as fixed");
    await settle();
    const fixed = sent().find((call) => String(call[0]).endsWith("/fixed"));
    expect(fixed?.[1]).toMatchObject({ body: { because: "the bounds check landed", fixed_in: 9 } });
  });

  it("names the build a code finding was stated fixed in", async () => {
    await drawn(true, {
      ...EVIDENCE,
      open: false,
      state: "fixed",
      fixed_in: { run: 9, built: "2026-10-02T00:00:00Z", commit: "0123456789abcdef" },
    });
    expect(mount.host().textContent).toContain("0123456789ab");
  });

  it("opens a link telling the page it opens nothing of this one", async () => {
    await drawn(false, {
      ...EVIDENCE,
      not_seen: "2026-10-02T00:00:00Z",
      compare: "https://git.example/compare/a...b",
    });
    const opened = [...mount.host().querySelectorAll('a[target="_blank"]')];
    expect(opened).toHaveLength(2);
    for (const a of opened) expect(a.getAttribute("rel")).toBe("noopener noreferrer");
  });

  it("names the commit its repository was at in the build it was last seen in and the next", async () => {
    await drawn(false, {
      ...EVIDENCE,
      last_commit: "0123456789abcdef0123",
      not_seen: "2026-10-02T00:00:00Z",
      not_seen_commit: "fedcba9876543210fedc",
    });
    expect(text()).toContain("at 0123456789ab");
    expect(text()).toContain("at fedcba987654");
  });

  it("offers no decision to somebody who only reads it", async () => {
    await drawn(false);
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(0);
  });

  it("names the decision standing at it in place of the form", async () => {
    await drawn(true, {
      ...EVIDENCE,
      decision_occurrence: {
        decision_id: 4,
        outcome: "dismissed",
        reason: "false_positive",
        reasoning: "",
        needs_approval: true,
        state: "proposed",
      },
    });
    expect(text()).toContain("Decision 4");
    expect(text()).toContain("Waiting for approval");
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(0);
  });

  it("sends a dismissal with its reason", async () => {
    await drawn(true);
    expect(mount.host().querySelectorAll('[role="radio"]')).toHaveLength(3);
    const sent = accept(() => ({ status: 201, data: { outcome: "dismissed", reasoning: "x" } }));
    pick(mount.host(), "Dismissed");
    change(mount.host().querySelector<HTMLSelectElement>("#code-finding-reason"), "false_positive");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "checked a line above");
    await press(mount.host(), "Propose");
    await settle();
    const [path, init] = sent()[0] ?? [];
    expect(path).toBe(
      "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/decision",
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

  it("gives it to a team, across the product, from among readers of security testing work", async () => {
    const searched = await drawn(true);
    const sent = answer("PUT", () => ({ status: 204 }));
    await holderBox();
    await press(mount.host(), "Kernel team");
    await settle();
    expect(searched()[0]).toBe("security-testing");
    const [path, init] = sent()[0] ?? [];
    expect(path).toBe(
      "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/assignment",
    );
    expect((init as { body: unknown }).body).toEqual({ team: "kernel" });
  });

  it("offers no holder once it is recorded as a flaw and security testing only", async () => {
    await drawn(
      true,
      {
        ...EVIDENCE,
        state: "recorded-as-flaw",
        recorded_as_flaw: { included_in_disclosure: false },
      },
      true,
    );
    expect(mount.host().querySelector('input[role="combobox"]')).toBeNull();
  });

  it("offers no holder once it is recorded as a flaw and included in disclosure", async () => {
    await drawn(
      true,
      {
        ...EVIDENCE,
        state: "recorded-as-flaw",
        recorded_as_flaw: { included_in_disclosure: true },
      },
      true,
    );
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
