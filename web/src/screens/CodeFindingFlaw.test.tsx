// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { CodeFinding } from "./CodeFinding";
import { accept, answer, mounted, screen, serve, settle } from "../test/mount";
import { change, pick, press, tick } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const AT = "/products/sonic/branches-and-tags/master/variants/broadcom/code-findings/abc";
const PATTERN =
  "/products/:product/branches-and-tags/:branch_or_tag/variants/:variant/code-findings/:occurrence";
const CODE_FINDING =
  "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}";

const CONFIRMED = {
  rule: "clang/unix.Malloc",
  at: { path: "src/zlib/a.c", start_line: 7, message: "p is leaked" },
  steps: [],
  related: [],
  kin: [],
  last_seen: "2026-10-01T00:00:00Z",
  open: true,
  state: "confirmed",
  decision_occurrence: { decision_id: 4, outcome: "confirmed", reasoning: "", state: "approved" },
};

const OFFER = {
  rule: "clang/unix.Malloc",
  prefix: "src/zlib",
  together: 0,
  seen: [
    { branch_or_tag: "master", variant: "broadcom" },
    { branch_or_tag: "master", variant: "mellanox" },
  ],
  suggestions: [
    {
      component: "zlib",
      from: "resembles",
      lacking: [{ branch_or_tag: "master", variant: "mellanox" }],
      unanalyzed: [{ branch_or_tag: "release", variant: "broadcom" }],
    },
    { from: "build", lacking: [], unanalyzed: [] },
  ],
  discloses: {
    authors: [
      {
        identity: "ana",
        name: "Ana",
        notes: [
          { decision: 7, body: "p leaks on the early return", written: "2026-10-01T00:00:00Z" },
          {
            decision: 7,
            comment: true,
            body: "seen on mellanox too",
            written: "2026-10-01T01:00:00Z",
          },
        ],
      },
    ],
    paths: ["src/zlib/a.c"],
    said: [{ path: "src/zlib/a.c", message: "p is leaked" }],
    snippets: 0,
    stripped: 1,
  },
};

async function drawn(evidence: object, hides = true, offer: object = OFFER) {
  serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          kind: "person",
          reach: [
            { product: "sonic", reads_internal: true, triages_internal: true, may_hide: hides },
          ],
          outcomes: [],
        },
      };
    if (path === CODE_FINDING) return { data: evidence };
    if (path === `${CODE_FINDING}/flaw`) return { data: offer };
    if (path === `${CODE_FINDING}/collaborators`) return { data: { items: [] } };
    if (path === "/v1/products/{product}/mentionable") return { data: { items: [] } };
    return undefined;
  });
  mount.render(screen(<CodeFinding />, AT, PATTERN));
  await settle();
}

const text = () => mount.host().textContent ?? "";

describe("recording as a flaw a code finding", () => {
  it("records the flaw against the builds holding the component picked", async () => {
    await drawn(CONFIRMED);
    const sent = accept(() => ({
      status: 201,
      data: { identifier: "SONIC-2026-000001", component: "zlib", builds: 1, occurrences: 1 },
    }));
    pick(mount.host(), "zlib");
    expect(text()).toContain("does not hold it");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "p leaks");
    await press(mount.host(), "Record as a flaw");
    await settle();
    const [path, init] = sent()[0] ?? [];
    expect(path).toBe(`${CODE_FINDING}/flaw`);
    expect((init as { body: unknown }).body).toEqual({
      builds: [{ branch_or_tag: "master", variant: "broadcom" }],
      summary: "p leaks",
      component: "zlib",
    });
    expect(text()).toContain("SONIC-2026-000001");
  });

  it("says a flaw in third-party code is reported upstream, and still records it", async () => {
    await drawn(CONFIRMED, true, { ...OFFER, third_party: true });
    expect(text()).toContain("report the flaw upstream");
    const sent = accept(() => ({
      status: 201,
      data: { identifier: "SONIC-2026-000001", component: "zlib", builds: 1, occurrences: 1 },
    }));
    pick(mount.host(), "zlib");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "inflate overflows");
    await press(mount.host(), "Record as a flaw");
    await settle();
    expect(sent()).toHaveLength(1);
    expect(text()).toContain("SONIC-2026-000001");
  });

  it("says nothing of an upstream for code of the product's own", async () => {
    await drawn(CONFIRMED);
    expect(text()).not.toContain("upstream");
  });

  it("says the code findings confirmed with it are recorded as a flaw with it", async () => {
    await drawn(CONFIRMED, true, { ...OFFER, together: 1 });
    expect(text()).toContain("Also records 1 other code finding confirmed with this one.");
  });

  it("picks no resembling component for the person", async () => {
    await drawn(CONFIRMED);
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "p leaks");
    const send = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Record as a flaw",
    );
    expect(send?.disabled).toBe(true);
  });

  it("records the flaw against a build holding the component that nothing analyzes", async () => {
    await drawn(CONFIRMED);
    const sent = accept(() => ({ status: 201, data: { identifier: "SONIC-2026-000003" } }));
    pick(mount.host(), "zlib");
    tick(mount.host(), "release · broadcom");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "p leaks");
    await press(mount.host(), "Record as a flaw");
    await settle();
    expect((sent()[0]?.[1] as { body: { builds: unknown } }).body.builds).toEqual([
      { branch_or_tag: "master", variant: "broadcom" },
      { branch_or_tag: "release", variant: "broadcom" },
    ]);
  });

  it("says what including it in disclosure publishes before it is sent", async () => {
    await drawn(CONFIRMED);
    expect(text()).not.toContain("Disclosed with the flaw");
    tick(mount.host(), "Include in disclosure");
    expect(text()).toContain("Disclosed with the flaw");
    expect(text()).toContain("readable by everyone signed in with public access to this product");
    expect(text()).toContain("Not included in published VEX or CSAF");
    expect(text()).toContain("Ana");
    expect(text()).toContain("p leaks on the early return");
    expect(text()).toContain("seen on mellanox too");
    expect(text()).toContain("p is leaked");
    expect(text()).toContain("Source snippets: not published · 1 removed at disclosure");
  });

  it("records the flaw against the build itself on every build it was seen in", async () => {
    await drawn(CONFIRMED);
    const sent = accept(() => ({ status: 201, data: { identifier: "SONIC-2026-000002" } }));
    pick(mount.host(), "The build itself");
    tick(mount.host(), "master · broadcom");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "p leaks");
    await press(mount.host(), "Record as a flaw");
    await settle();
    expect((sent()[0]?.[1] as { body: unknown }).body).toEqual({
      builds: [{ branch_or_tag: "master", variant: "mellanox" }],
      summary: "p leaks",
    });
  });

  it("is offered to nobody who may not record an undisclosed flaw", async () => {
    await drawn(CONFIRMED, false);
    expect(text()).not.toContain("Record as a flaw");
  });
});

describe("a code finding recorded as a flaw", () => {
  const RECORDED = {
    ...CONFIRMED,
    state: "recorded-as-flaw",
    recorded_as_flaw: {
      flaw: "SONIC-2026-000001",
      included_in_disclosure: false,
      disclosed: false,
      recorded_by: "ana",
      recorded_at: "2026-10-02T00:00:00Z",
    },
  };

  it("links its flaw and includes it in disclosure", async () => {
    await drawn(RECORDED);
    const sent = answer("PUT", () => ({ status: 204 }));
    expect(mount.host().querySelector('a[href*="SONIC-2026-000001"]')).not.toBeNull();
    expect(text()).toContain("Internal only");
    expect(text()).not.toContain("Decision");
    expect(text()).toContain("Grants reading this code finding only.");
    // What including it publishes is said before it is made.
    expect(text()).toContain("p leaks on the early return");
    await press(mount.host(), "Include in disclosure");
    await settle();
    expect(sent()[0]?.[0]).toBe(`${CODE_FINDING}/flaw/disclosure`);
  });

  it("says including it takes the code findings linked to its flaw", async () => {
    await drawn(RECORDED, true, { ...OFFER, together: 2 });
    expect(text()).toContain("Goes with 2 other code findings linked to this flaw.");
  });

  it("withdraws the flaw with a reason", async () => {
    await drawn(RECORDED);
    const sent = accept(() => ({ status: 204 }));
    await press(mount.host(), "Withdraw flaw…");
    change(
      mount.host().querySelector("textarea"),
      "recorded as a flaw against the wrong component",
    );
    await press(mount.host(), "Withdraw flaw");
    await settle();
    expect(sent()[0]?.[0]).toBe(`${CODE_FINDING}/flaw/withdrawal`);
    expect(sent()[0]?.[1]).toMatchObject({
      body: { because: "recorded as a flaw against the wrong component" },
    });
  });

  it("offers no change to disclosure once its flaw is disclosed", async () => {
    await drawn({
      ...RECORDED,
      recorded_as_flaw: {
        ...RECORDED.recorded_as_flaw,
        included_in_disclosure: true,
        disclosed: true,
      },
    });
    expect(text()).not.toContain("Take out of disclosure");
    expect(text()).not.toContain("Withdraw flaw");
    expect(text()).not.toContain("Collaborators");
  });
});
