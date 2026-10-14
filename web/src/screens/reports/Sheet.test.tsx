// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { mounted, screen, serve, settle } from "../../test/mount";
import { Effort } from "./Effort";
import { Overview } from "./Overview";
import { Scrutiny } from "./Scrutiny";
import { Sheet } from "./Sheet";
import { windowStart } from "./Window";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const printed = () => mount.host().querySelector(".printhead p")?.textContent ?? "";

describe("a printed sheet's header", () => {
  it("states what the figures cover where that is not the scope", () => {
    mount.render(
      screen(
        <Sheet name="X" answers="y." of="sonic, every branch and variant" asked="team platform">
          <p />
        </Sheet>,
      ),
    );
    expect(printed()).toContain("sonic, every branch and variant · team platform");
    expect(printed()).not.toContain("every variant ·");
  });

  it("names the team an effort sheet is narrowed to", async () => {
    serve(() => ({ data: { items: [], total: 0 } }));
    mount.render(screen(<Effort />, "/reports/effort-by-component?team=platform"));
    await settle();
    expect(printed()).toContain("team platform");
  });

  it("says an effort sheet's list was cut", async () => {
    const row = {
      product: "sonic",
      component: "openssl",
      claims: 1,
      decisions: 1,
      people: 1,
      promised: 0,
      dismissed: 0,
      deferred: 0,
    };
    serve((path) =>
      path === "/v1/effort"
        ? { data: { items: Array.from({ length: 50 }, () => row), total: 80 } }
        : { data: { items: [], total: 0 } },
    );
    mount.render(screen(<Effort />, "/reports/effort-by-component"));
    await settle();
    expect(mount.host().textContent).toContain("80");
  });
});

describe("the approval quality figure", () => {
  it("counts from the day its links open the record from", async () => {
    const reads = serve(() => ({ data: { items: [], alone: [] } }));
    mount.render(screen(<Scrutiny />, "/reports/approval-quality?days=30"));
    await settle();
    const calls = reads.mock.calls as unknown as [string, unknown][];
    const asked = calls.find(([path]) => path === "/v1/approvals/scrutiny")?.[1] as {
      params: { query: Record<string, unknown> };
    };
    expect(asked.params.query.from).toBe(windowStart(30));
    expect(asked.params.query.days).toBeUndefined();
  });
});

describe("the program overview's figures", () => {
  it("count from the day their links open the record from", async () => {
    const reads = serve(() => ({ data: { items: [] } }));
    mount.render(screen(<Overview />, "/reports/program-overview?days=30"));
    await settle();
    const calls = reads.mock.calls as unknown as [string, unknown][];
    for (const path of ["/v1/remediation", "/v1/measures"]) {
      const asked = calls.find(([called]) => called === path)?.[1] as {
        params: { query: Record<string, unknown> };
      };
      expect(asked.params.query.from).toBe(windowStart(30));
      expect(asked.params.query.days).toBeUndefined();
    }
  });
});
