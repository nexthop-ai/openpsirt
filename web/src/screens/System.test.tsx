// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { System } from "./System";
import {
  accept,
  client,
  mounted,
  screen,
  serve,
  settle,
  watchInvalidations,
  type Answer,
} from "../test/mount";
import { only, press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const READS: Record<string, Answer> = {
  "/v1/vulnerability-data": {
    data: {
      version: "v6:2026-01-01",
      moved_at: "2026-01-01T00:00:00Z",
      stale: true,
      stale_after: "72h",
      records: { version: "2026-01-02", moved_at: "2026-01-02T00:00:00Z", stale: true },
    },
  },
  "/v1/work/set-aside": {
    data: {
      waiting: [
        { kind: "ingest", waiting: 10, limit: 10 },
        { kind: "scan", waiting: 1, limit: 50 },
      ],
      items: [
        {
          id: 9,
          kind: "scan",
          reference: "target:4",
          attempts: 5,
          stopped_at: "2026-01-01T00:00:00Z",
        },
      ],
      total: 3,
    },
  },
  "/v1/patch-branches": {
    data: { on: false, looked: 0, commits: 0, links: 0, total: 0, repositories: [] },
  },
  "/v1/upstream/unanswered": {
    data: {
      ours: ["acme-internal"],
      whole: false,
      total: 4,
      items: [
        { purl: "pkg:npm/acme-internal@1", why: "ours", checked: "2026-01-01T00:00:00Z" },
        { purl: "pkg:npm/%zz@1", ecosystem: "npm", why: "unreadable" },
        { purl: "pkg:pypi/gone@1", ecosystem: "pypi" },
      ],
    },
  },
};

async function drawn(reads = READS) {
  serve((path) => reads[path] ?? { data: { items: [], total: 0, repositories: [] } });
  const sent = accept(() => ({ data: {} }));
  const queries = client();
  const invalidated = watchInvalidations(queries);
  mount.render(screen(<System />, "/", "*", queries));
  await settle();
  return { sent, invalidated };
}

const text = () => mount.host().textContent ?? "";

describe("the deployment's own state", () => {
  it("puts back the failed job named, and reads the list again", async () => {
    const { sent, invalidated } = await drawn();
    await press(mount.host(), "Put back");
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/work/set-aside/{id}/retry");
    expect(init.params?.path).toEqual({ id: 9 });
    expect(invalidated()).toContain("set-aside");
    expect(text()).toContain("Showing 1 of 3.");
    expect(text()).toContain("nothing said");
  });

  it("marks a kind at its limit, and no other", async () => {
    await drawn();
    expect(mount.host().querySelectorAll(".state.warn")).toHaveLength(1);
  });

  it("says when the data and the CVE records stopped moving", async () => {
    await drawn();
    expect(text()).toContain("v6:2026-01-01");
    expect(mount.host().querySelectorAll(".state.bad")).toHaveLength(2);
  });

  it("says nothing is narrowed where no CVE record snapshot was read", async () => {
    await drawn({
      ...READS,
      "/v1/vulnerability-data": { data: { version: "v6", stale: false } },
    });
    expect(text()).toContain("none read, so nothing is narrowed");
  });

  it("names why upstream could not answer, and that the count is a floor", async () => {
    await drawn();
    expect(text()).toContain("Held back: acme-internal");
    expect(text()).toContain("held back, ours");
    expect(text()).toContain("identifier cannot be read");
    expect(text()).toContain("not known, or refused");
    expect(text()).toContain("4 without an answer, 3 shown");
    expect(text()).toContain("The count is a floor.");
  });
});
