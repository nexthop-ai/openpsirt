// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { type ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AnalysisCoverage } from "./AnalysisCoverage";
import { AnalyzerPrecision } from "./AnalyzerPrecision";
import { CodeFindingsByRelease } from "./CodeFindingsByRelease";
import { TimeToFix, TimeToJudge } from "./CodeFindingTiming";
import { client, mounted, screen, serve, settle } from "../../test/mount";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());
afterEach(() => vi.restoreAllMocks());

const wait = (count: number, median: number, tier?: string) => ({
  tier,
  count,
  median_days: median,
  p90_days: median * 2,
  worst_days: median * 3,
});

const JUDGE = "/v1/products/{product}/code-finding-time-to-judge";
const FIX = "/v1/products/{product}/code-finding-time-to-fix";
const PRECISION = "/v1/products/{product}/code-finding-precision";
const COVERAGE = "/v1/products/{product}/analysis-coverage";
const RELEASES = "/v1/products/{product}/code-findings-by-release";

const ANSWERS: Record<string, object> = {
  [JUDGE]: {
    judged: { all: wait(3, 2.5), by_tier: [wait(2, 1, "memory-safety"), wait(1, 9, "other")] },
    waiting: [
      { label: "Under a week", waiting: 1, by_tier: { other: 1 } },
      { label: "Over three months", waiting: 2, by_tier: { "memory-safety": 2 } },
    ],
    oldest: "2026-06-01",
    no_longer_detected: 4,
  },
  [FIX]: {
    fixed: { all: wait(2, 12), by_tier: [wait(2, 12, "input")] },
    dismissed: 1,
    no_longer_detected: { all: wait(5, 30), by_tier: [] },
  },
  [PRECISION]: {
    by_series: [
      {
        series: "cppcheck/default",
        judged: 4,
        noise_share: 0.75,
        dismissed: 2,
        not_security: 0,
        ruled: 1,
        confirmed: 1,
        fixed: 0,
        unjudged: 6,
      },
    ],
    by_rule: [
      {
        series: "cppcheck/default",
        rule: "nullPointer",
        judged: 3,
        noise_share: 1,
        dismissed: 2,
        not_security: 0,
        ruled: 1,
        confirmed: 0,
        fixed: 0,
        unjudged: 0,
      },
    ],
    suppression_rules: [
      {
        id: 1,
        rule: "nullPointer",
        path: "vendor/",
        state: "approved",
        covering: 7,
        approved_covering: 5,
      },
    ],
  },
  [COVERAGE]: {
    since: "2026-07-31",
    until: "2026-10-30",
    quiet: 1,
    items: [
      {
        branch_or_tag: "master",
        branch_or_tag_name: "master",
        variant: "broadcom",
        variant_name: "Broadcom",
        series: "clang-tidy/default",
        method: "sast",
        past_end_of_life: false,
        quiet: true,
        last_arrived: "2026-10-20T00:00:00Z",
        expected_days: 1,
        allowed_days: 3,
        silent_days: 10,
        applied_runs: 30,
        not_comparable_runs: 0,
        failed_runs: 0,
      },
      {
        branch_or_tag: "master",
        branch_or_tag_name: "master",
        variant: "broadcom",
        variant_name: "Broadcom",
        series: "cppcheck/default",
        method: "sast",
        past_end_of_life: false,
        quiet: false,
        last_arrived: "2026-10-01T00:00:00Z",
        not_comparable: "units-short",
        units_expected: 100,
        units_analyzed: 40,
        expected_days: 91,
        allowed_days: 273,
        silent_days: 29,
        applied_runs: 1,
        not_comparable_runs: 1,
        failed_runs: 2,
      },
    ],
  },
  [RELEASES]: {
    releases: [
      {
        branch_or_tag: "v1.1",
        branch_or_tag_name: "v1.1",
        cut: "2026-06-01",
        not_fixed: 9,
        by_tier: { "memory-safety": 4 },
        open: 6,
        dismissed: 2,
        no_longer_detected: 1,
      },
      {
        branch_or_tag: "v1.2",
        branch_or_tag_name: "v1.2",
        cut: "2026-09-01",
        not_fixed: 3,
        by_tier: {},
        open: 3,
        dismissed: 0,
        no_longer_detected: 0,
      },
    ],
  },
};

const PAGES: [string, string, () => ReactElement][] = [
  ["time-to-judge", JUDGE, () => <TimeToJudge />],
  ["time-to-fix", FIX, () => <TimeToFix />],
  ["analyzer-precision", PRECISION, () => <AnalyzerPrecision />],
  ["analysis-coverage", COVERAGE, () => <AnalysisCoverage />],
  ["code-findings-by-release", RELEASES, () => <CodeFindingsByRelease />],
];

async function drawn(page: () => ReactElement, at: string, reads: boolean) {
  window.sessionStorage.setItem("openpsirt.scope", JSON.stringify({ product: "sonic" }));
  const session = {
    identity: "ana",
    name: "Ana",
    kind: "person",
    reach: [{ product: "sonic", reads_public: true, reads_security_testing: reads }],
    outcomes: [],
  };
  const queries = client();
  queries.setQueryData(["whoami"], session);
  const spy = serve((path) => {
    if (path === "/v1/session/me") return { data: session };
    const answer = ANSWERS[path];
    return answer ? { data: answer } : undefined;
  });
  mount.render(screen(page(), at, "*", queries));
  await settle();
  return spy;
}

const text = () => mount.host().textContent ?? "";
const asked = (spy: Awaited<ReturnType<typeof drawn>>, path: string) =>
  (
    spy.mock.calls as unknown as [string, { params?: { query?: Record<string, unknown> } }][]
  ).filter(([each]) => each === path);
const link = (words: string) => {
  const found = [...mount.host().querySelectorAll("a")].find((each) => each.textContent === words);
  return new URL(found?.getAttribute("href") ?? "", "http://x");
};

describe.each(PAGES)("the %s page", (slug, path, page) => {
  it("asks for nothing where the reader does not read security testing material in the product", async () => {
    const spy = await drawn(page, `/analytics/${slug}`, false);
    expect(asked(spy, path)).toEqual([]);
    expect(text()).toContain("Nothing to list.");
  });

  it("offers its figures as a file asked as the screen asked", async () => {
    await drawn(page, `/analytics/${slug}?series=cppcheck/default`, true);
    const csv = link("CSV");
    expect(csv.pathname).toBe(`${path.replace("{product}", "sonic")}.csv`);
    expect(csv.searchParams.get("series")).toBe("cppcheck/default");
  });

  it("says nothing of reviewing code by any other means", async () => {
    await drawn(page, `/analytics/${slug}`, true);
    expect(text()).not.toMatch(/\bAI\b|model|LLM/);
  });
});

describe("time to judge and time to fix", () => {
  it("draws the median and the 90th percentile per tier, and the queue by age", async () => {
    await drawn(() => <TimeToJudge />, "/analytics/time-to-judge", true);
    const rows = [...mount.host().querySelectorAll("tbody tr")].map((each) => each.textContent);
    expect(rows[0]).toBe("All tiers32.5 days5 days7.5 days");
    expect(rows[1]).toContain("Memory safety");
    expect(text()).toContain("Over three months2");
    expect(text()).toContain("Oldest opened 2026-06-01.");
    expect(link("4 no longer detected").searchParams.get("state")).toBe("no-longer-detected");
  });

  it("asks for the window picked", async () => {
    const spy = await drawn(() => <TimeToJudge />, "/analytics/time-to-judge?weeks=52", true);
    expect(asked(spy, JUDGE).at(-1)?.[1].params?.query).toMatchObject({ weeks: 52 });
  });

  it("leaves dismissals out of fixed and times what is no longer detected apart", async () => {
    await drawn(() => <TimeToFix />, "/analytics/time-to-fix", true);
    expect(text()).toContain("1 closed as fixed and dismissed is left out.");
    const panels = [...mount.host().querySelectorAll("section.panel")].map(
      (each) => each.textContent,
    );
    expect(panels[0]).toContain("12 days");
    expect(panels[1]).toContain("No longer detected, now");
    expect(panels[1]).toContain("30 days");
    expect(panels[1]).toContain("Missed isn’t fixed");
  });
});

describe("analyzer precision", () => {
  it("draws the noise share per series and rule, and what each suppression rule covers", async () => {
    await drawn(() => <AnalyzerPrecision />, "/analytics/analyzer-precision", true);
    const rows = [...mount.host().querySelectorAll("tbody tr")].map((each) => each.textContent);
    expect(rows[0]).toContain("cppcheck/default475%");
    expect(rows[1]).toContain("nullPointercppcheck/default3100%");
    expect(rows[2]).toBe("nullPointer under vendor/approved——75");
  });
});

describe("analysis coverage", () => {
  it("names a series gone quiet against its own interval", async () => {
    await drawn(() => <AnalysisCoverage />, "/analytics/analysis-coverage", true);
    expect(text()).toContain("1 gone quiet");
    const rows = [...mount.host().querySelectorAll("tbody tr")].map((each) => each.textContent);
    expect(rows[0]).toContain("Gone quiet");
    expect(rows[0]).toContain("10 days silent");
    expect(rows[1]).toContain("Not comparable · analyzed fewer units than expected");
    expect(rows[1]).toContain("91 days");
    expect(rows[1]).toContain("40 of 100");
  });
});

describe("code findings by release", () => {
  it("draws a bar per release in the order they went out, and opens each count on the queue", async () => {
    await drawn(() => <CodeFindingsByRelease />, "/analytics/code-findings-by-release", true);
    const bars = [...mount.host().querySelectorAll(".chart rect title")].map(
      (each) => each.textContent,
    );
    expect(bars).toEqual(["v1.1: 9 not fixed", "v1.2: 3 not fixed"]);
    const dismissed = link("2");
    expect(dismissed.pathname).toBe("/products/sonic/code-findings");
    expect(dismissed.searchParams.get("branch_or_tag")).toBe("v1.1");
    expect(dismissed.searchParams.get("state")).toBe("dismissed");
  });
});
