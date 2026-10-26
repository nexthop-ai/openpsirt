// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Lead } from "./Lead";
import { accept, answer, mounted, screen, serve, settle } from "../test/mount";
import { change, pick, press, tick } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const AT = "/products/sonic/streams/master/variants/broadcom/leads/abc";
const PATTERN = "/products/:product/streams/:stream/variants/:variant/leads/:place";
const LEAD = "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}";

const CONFIRMED = {
  rule: "clang/unix.Malloc",
  at: { path: "src/zlib/a.c", start_line: 7, message: "p is leaked" },
  steps: [],
  related: [],
  kin: [],
  last_seen: "2026-10-01T00:00:00Z",
  open: true,
  state: "confirmed",
  decision: { claim_id: 4, outcome: "confirmed", reasoning: "", state: "approved" },
};

const OFFER = {
  rule: "clang/unix.Malloc",
  prefix: "src/zlib",
  seen: [
    { stream: "master", variant: "broadcom" },
    { stream: "master", variant: "mellanox" },
  ],
  suggestions: [
    {
      component: "zlib",
      from: "resembles",
      lacking: [{ stream: "master", variant: "mellanox" }],
      unanalyzed: [{ stream: "release", variant: "broadcom" }],
    },
    { from: "build", lacking: [], unanalyzed: [] },
  ],
  discloses: {
    authors: [{ identity: "ana", name: "Ana", writings: 2 }],
    paths: ["src/zlib/a.c"],
    messages: 1,
    snippets: 0,
    stripped: 1,
  },
};

async function drawn(evidence: object, hides = true) {
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
    if (path === LEAD) return { data: evidence };
    if (path === `${LEAD}/hand-off`) return { data: OFFER };
    if (path === `${LEAD}/collaborators`) return { data: { items: [] } };
    if (path === "/v1/products/{product}/mentionable") return { data: { items: [] } };
    return undefined;
  });
  mount.render(screen(<Lead />, AT, PATTERN));
  await settle();
}

const text = () => mount.host().textContent ?? "";

describe("handing off a lead", () => {
  it("records the flaw against the builds holding the component picked", async () => {
    await drawn(CONFIRMED);
    const sent = accept(() => ({
      status: 201,
      data: { identifier: "SONIC-2026-000001", component: "zlib", builds: 1, places: 1 },
    }));
    pick(mount.host(), "zlib");
    expect(text()).toContain("does not hold it");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "p leaks");
    await press(mount.host(), "Hand off");
    await settle();
    const [path, init] = sent()[0] ?? [];
    expect(path).toBe(`${LEAD}/hand-off`);
    expect((init as { body: unknown }).body).toEqual({
      builds: [{ stream: "master", variant: "broadcom" }],
      summary: "p leaks",
      component: "zlib",
    });
    expect(text()).toContain("SONIC-2026-000001");
  });

  it("picks no resembling component for the person", async () => {
    await drawn(CONFIRMED);
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "p leaks");
    const send = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Hand off",
    );
    expect(send?.disabled).toBe(true);
  });

  it("records the flaw against a build holding the component that nothing analyzes", async () => {
    await drawn(CONFIRMED);
    const sent = accept(() => ({ status: 201, data: { identifier: "SONIC-2026-000003" } }));
    pick(mount.host(), "zlib");
    tick(mount.host(), "release · broadcom");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "p leaks");
    await press(mount.host(), "Hand off");
    await settle();
    expect((sent()[0]?.[1] as { body: { builds: unknown } }).body.builds).toEqual([
      { stream: "master", variant: "broadcom" },
      { stream: "release", variant: "broadcom" },
    ]);
  });

  it("says what a move discloses before it is sent", async () => {
    await drawn(CONFIRMED);
    expect(text()).not.toContain("Disclosed with the flaw");
    pick(mount.host(), "Move into the case");
    expect(text()).toContain("What Ana wrote about it");
    expect(text()).toContain("1 source snippets are removed at disclosure");
  });

  it("records the flaw against the build itself on every build it was seen in", async () => {
    await drawn(CONFIRMED);
    const sent = accept(() => ({ status: 201, data: { identifier: "SONIC-2026-000002" } }));
    pick(mount.host(), "The build itself");
    tick(mount.host(), "master · broadcom");
    change(mount.host().querySelector<HTMLTextAreaElement>("textarea"), "p leaks");
    await press(mount.host(), "Hand off");
    await settle();
    expect((sent()[0]?.[1] as { body: unknown }).body).toEqual({
      builds: [{ stream: "master", variant: "mellanox" }],
      summary: "p leaks",
    });
  });

  it("is offered to nobody who may not record an undisclosed flaw", async () => {
    await drawn(CONFIRMED, false);
    expect(text()).not.toContain("Hand off");
  });
});

describe("a handed-off lead", () => {
  const HANDED = {
    ...CONFIRMED,
    state: "handed-off",
    handoff: {
      flaw: "SONIC-2026-000001",
      moved: false,
      disclosed: false,
      handed_by: "ana",
      handed_at: "2026-10-02T00:00:00Z",
    },
  };

  it("links its flaw and moves it into the case", async () => {
    await drawn(HANDED);
    const sent = answer("PUT", () => ({ status: 204 }));
    expect(mount.host().querySelector('a[href*="SONIC-2026-000001"]')).not.toBeNull();
    expect(text()).toContain("kept internal");
    expect(text()).not.toContain("Decision");
    expect(text()).toContain("Grants reading this lead only.");
    // What the move discloses is said before it is made.
    expect(text()).toContain("What Ana wrote about it");
    await press(mount.host(), "Move into the case");
    await settle();
    expect(sent()[0]?.[0]).toBe(`${LEAD}/move`);
  });

  it("offers no move once its flaw is disclosed", async () => {
    await drawn({ ...HANDED, handoff: { ...HANDED.handoff, moved: true, disclosed: true } });
    expect(text()).not.toContain("Take out of the case");
    expect(text()).not.toContain("Collaborators");
  });

  it("says a stub is part of a case the reader is not on", async () => {
    await drawn(
      {
        ...HANDED,
        handoff: undefined,
        withheld: true,
        at: { path: "src/zlib/a.c", start_line: 7 },
        decision: undefined,
      },
      false,
    );
    expect(text()).toContain("Part of a case you are not on");
    expect(text()).not.toContain("Decision");
  });
});
