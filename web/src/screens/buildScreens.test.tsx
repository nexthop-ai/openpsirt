// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Decision } from "./Decision";
import { InventoryChanges } from "./InventoryChanges";
import { Run } from "./Run";
import { Upgrades } from "./Upgrades";
import { location, mounted, screen, serve, settle, type Answer } from "../test/mount";
import { press, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const text = () => mount.host().textContent ?? "";
const BUILD = "/products/sonic/streams/master/variants/arm";
const BUILT = "/products/:product/streams/:stream/variants/:variant";

describe("a decision's address", () => {
  it("forwards to the claim the decision belongs to", async () => {
    serve(() => ({ data: { decision: { claim_id: 41 } } }));
    mount.render(screen(<Decision />, "/decisions/9", "/decisions/:id"));
    await settle();
    expect(location()).toBe("/claims/41");
  });

  it("says a decision naming no claim does, rather than forwarding nowhere", async () => {
    serve(() => ({ data: { decision: {} } }));
    mount.render(screen(<Decision />, "/decisions/9", "/decisions/:id"));
    await settle();
    expect(text()).toContain("That decision names no claim.");
  });
});

describe("one scan run", () => {
  async function drawn(run: Answer) {
    serve(() => run);
    mount.render(screen(<Run />, `${BUILD}/runs/7`, `${BUILT}/runs/:run`));
    await settle();
  }

  it("links the findings it opened, and leaves out a band it opened none in", async () => {
    await drawn({
      data: {
        run_id: 7,
        scanner: "grype",
        started_at: "2026-01-01T00:00:00Z",
        finished_at: "2026-01-01T00:04:00Z",
        caution: "the database is old",
        opened: { total: 3, critical: 1, low: 2 },
        opened_exploited: 1,
        closed: { total: 0 },
      },
    });
    const link = Array.from(mount.host().querySelectorAll("a")).find(
      (a) => a.textContent === "Opened findings →",
    );
    expect(link?.getAttribute("href")).toContain("opened_by_run=7");
    expect(text()).toContain("1 critical");
    expect(text()).not.toContain("0 high");
    expect(text()).toContain("1 known exploited");
    expect(text()).toContain("Nothing changed.");
    expect(text()).toContain("It qualified its answer");
  });

  it("says a run still going is still going, and what a failed one said", async () => {
    await drawn({ data: { run_id: 7, scanner: "grype", failure: "the scanner exited 2" } });
    expect(text()).toContain("still running");
    expect(text()).toContain("the scanner exited 2");
  });
});

describe("the upgrades a build is waiting on", () => {
  it("puts what is late first and says how many are late", async () => {
    serve(() => ({
      data: {
        items: [
          { fold: "a", upstream: "zlib", to: "1.3", state: "landed", issues: 2 },
          { fold: "b", upstream: "openssl", to: "3.0.9", state: "planned", issues: 1, claim_id: 5 },
          { fold: "c", upstream: "curl", to: "8.6", state: "lapsed", issues: 4, held_by: "bo" },
        ],
      },
    }));
    mount.render(screen(<Upgrades />, `${BUILD}/upgrades`, `${BUILT}/upgrades`));
    await settle();
    const first = Array.from(mount.host().querySelectorAll("tbody tr")).map(
      (tr) => tr.querySelector("td")?.textContent,
    );
    expect(first[0]).toContain("curl");
    expect(first[2]).toContain("zlib");
    expect(text()).toContain("1 upgrade is past the date promised");
    expect(mount.host().querySelector("h2 .n")?.textContent).toBe("2");
    expect(text()).toContain("landed");
  });
});

describe("what one upload changed", () => {
  it("asks for one kind of change from the first page", async () => {
    const spy = serve((path, init) =>
      path.endsWith("/changes")
        ? {
            data: {
              items: [{ name: "zlib", change: "changed", before: ["1.2"], after: ["1.3"] }],
              total: (init as Init).params?.query?.change ? 1 : 450,
            },
          }
        : undefined,
    );
    mount.render(
      screen(<InventoryChanges />, `${BUILD}/scans/3/changes`, `${BUILT}/scans/:scan/changes`),
    );
    await settle();
    await press(mount.host(), "Next");
    await settle();
    await press(mount.host(), "Removed");
    await settle();
    const asked = (spy.mock.calls as unknown as [string, Init][]).map(
      ([, init]) => init.params?.query,
    );
    expect(asked).toContainEqual({ limit: 200, offset: 200 });
    expect(asked.at(-1)).toEqual({ limit: 200, offset: 0, change: "removed" });
  });
});
