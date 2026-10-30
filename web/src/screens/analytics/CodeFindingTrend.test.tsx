// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CodeFindingTrend } from "./CodeFindingTrend";
import { client, mounted, screen, serve, settle } from "../../test/mount";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());
afterEach(() => vi.restoreAllMocks());

const TREND = "/v1/products/{product}/code-finding-trend";

const POINT = (at: string, notFixed: number, opened: number, fixed: number) => ({
  at,
  not_fixed: notFixed,
  opened,
  fixed,
  by_tier: { "memory-safety": opened, input: 0, resource: 0, other: notFixed - opened },
  by_series: { "clang-tidy/default": notFixed - opened, "codeql/default": opened },
  by_method: { sast: notFixed },
});

const ANSWER = {
  points: [POINT("2026-10-23", 3, 0, 0), POINT("2026-10-30", 3, 1, 1)],
  markers: [
    {
      at: "2026-10-29",
      series: "cppcheck/default",
      change: "rules",
      from: "2",
      to: "3",
      runs: 1,
    },
    {
      at: "2026-10-30",
      series: "semgrep/default",
      change: "not-comparable",
      reason: "units-short",
      runs: 2,
    },
  ],
  no_longer_detected: 1,
};

async function drawn(readsSecurityTesting: boolean, at = "/analytics/code-findings-over-time") {
  window.sessionStorage.setItem("openpsirt.scope", JSON.stringify({ product: "sonic" }));
  const session = {
    identity: "ana",
    name: "Ana",
    kind: "person",
    reach: [{ product: "sonic", reads_security_testing: readsSecurityTesting }],
    outcomes: [],
  };
  const queries = client();
  queries.setQueryData(["whoami"], session);
  const spy = serve((path) => {
    if (path === "/v1/session/me") return { data: session };
    if (path === TREND) return { data: ANSWER };
    return undefined;
  });
  mount.render(screen(<CodeFindingTrend />, at, "*", queries));
  await settle();
  return spy;
}

const text = () => mount.host().textContent ?? "";
const paths = (spy: Awaited<ReturnType<typeof drawn>>) =>
  (
    spy.mock.calls as unknown as [string, { params?: { query?: Record<string, unknown> } }][]
  ).filter(([path]) => path === TREND);

describe("code findings over time", () => {
  it("asks for no trend where the reader does not read security testing material in the product", async () => {
    const spy = await drawn(false);
    expect(paths(spy)).toEqual([]);
    expect(text()).toContain("Nothing to list.");
    expect(text()).toContain("You don't read code findings in any product.");
  });

  it("says each analyzer change in the week it fell in", async () => {
    await drawn(true);
    const rows = [...mount.host().querySelectorAll("tbody tr")].map((each) => each.textContent);
    expect(rows[1]).toContain("cppcheck/default: rule set changed from 2 rules to 3 rules");
    expect(rows[1]).toContain(
      "semgrep/default: not comparable, analyzed fewer units than expected (2 builds)",
    );
    expect(rows[0]).not.toContain("cppcheck");
    expect(mount.host().querySelectorAll(".chart .mark").length).toBe(1);
  });

  it("splits by tier until another split is picked, and the file asks what the screen asked", async () => {
    await drawn(true, "/analytics/code-findings-over-time?series=clang-tidy/default");
    expect(text()).toContain("Memory safety");
    const series = [...mount.host().querySelectorAll("button")].find(
      (each) => each.textContent === "Series",
    );
    act(() => series?.click());
    await settle();
    expect(text()).toContain("codeql/default");
    const csv = [...mount.host().querySelectorAll("a")].find((each) => each.textContent === "CSV");
    const asked = new URL(csv?.getAttribute("href") ?? "", "http://x");
    expect(asked.pathname).toBe("/v1/products/sonic/code-finding-trend.csv");
    expect(asked.searchParams.get("series")).toBe("clang-tidy/default");
  });

  it("opens today's no-longer-detected count on the queue in that state, narrowed alike", async () => {
    await drawn(true, "/analytics/code-findings-over-time?method=sast");
    const link = [...mount.host().querySelectorAll("a")].find(
      (each) => each.textContent === "1 no longer detected",
    );
    const asked = new URL(link?.getAttribute("href") ?? "", "http://x");
    expect(asked.pathname).toBe("/products/sonic/code-findings");
    expect(asked.searchParams.get("state")).toBe("no-longer-detected");
    expect(asked.searchParams.get("method")).toBe("sast");
  });

  it("asks for a build before reading at or under a component", async () => {
    const spy = await drawn(true, "/analytics/code-findings-over-time?beneath=libnl");
    expect(paths(spy)).toEqual([]);
    expect(text()).toContain("This needs one build.");
  });

  it("says nothing of reviewing code by any other means", async () => {
    await drawn(true);
    expect(text()).not.toMatch(/\bAI\b|model|LLM/);
  });
});
