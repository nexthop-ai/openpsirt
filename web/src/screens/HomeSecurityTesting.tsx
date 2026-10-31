// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQueries, useQuery, type UseQueryResult } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import {
  codeFindingsQuery,
  type AnalysisCoverage,
  type CodeFindingMarker,
  type CodeFindingMethod,
  type CodeFindingTrend,
  type CodeFindings,
} from "../api/codeFindings";
import { unwrap } from "../api/queries";
import { counted, holding, type Holding } from "../app/families";
import { analyticsReportAt, codeFindingsAcrossAt, codeFindingsAt } from "../app/routes";
import { useScope, type Scoped } from "../app/scope";
import type { Who } from "../app/session";
import { Pace, Stack, type StackPart } from "../ui/Charts";
import { Count } from "../ui/Count";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { HeldLine } from "../ui/HeldLine";
import { Loading } from "../ui/Loading";
import { CODE_FINDING_METHODS } from "./codeFindings";
import { TIERS, codeTrendAt, marksOf } from "./codeTrend";

// Home's Security testing figures: the code findings to judge and waiting for
// a judgment, this week's new and fixed, what is no longer detected, the
// analyzers gone quiet, and twelve weeks of what is not fixed. Counted per
// testing method and never beside a dependency figure.
//
// A series belongs to one product, so the trend, the waits and the coverage are
// asked per product and added together across products, which is sound
// because a code finding belongs to one product. The counts of the queue are
// one read across products. Every product counted is one where the reader
// reads security testing material, and the head says how many.

// The weeks home's charts cover, as the dependency trend does.
const WEEKS = 12;
// The weeks the analyzer run counts cover. Home reads only whether a series
// is quiet and when it last ran, which no window changes.
const COVERAGE_WEEKS = 1;

const TIER_COLORS = [
  "var(--sev-critical)",
  "var(--sev-high)",
  "var(--sev-medium)",
  "var(--sev-low)",
];

const WORDS = {
  line: "not fixed",
  what: "Code findings not fixed",
  fresh: "new code findings",
  done: "fixed",
};

// The products whose code findings the figures count: the one picked, where
// the reader reads them there, or every product they read them in.
export function codeProducts(who: Who, product: string | undefined): string[] {
  if (product) return counted(holding(who, "code", product)) ? [product] : [];
  return (who.reach ?? []).filter((can) => can.reads_security_testing).map((can) => can.product);
}

// The narrowing a figure of one product takes from the picker.
function narrowing(at: Scoped) {
  return {
    branch_or_tag: at.branch_or_tag || undefined,
    variant: at.variant || undefined,
  };
}

// Every product's analysis coverage, for the quiet series and the newest run.
// Shared with the status panel, which asks the same reads.
export function useCoverages(products: string[], at: Scoped): UseQueryResult<AnalysisCoverage>[] {
  const asked = { ...narrowing(at), weeks: COVERAGE_WEEKS };
  return useQueries({
    queries: products.map((product) => ({
      queryKey: ["code-findings", product, "coverage", asked],
      queryFn: async () =>
        unwrap(
          await api.GET("/v1/products/{product}/analysis-coverage", {
            params: { path: { product }, query: codeFindingsQuery(asked) },
          }),
        ),
      retry: false,
    })),
  });
}

// The queue's counts at the scope: one product's, or every product's the
// reader reads security testing material in, in one read. Narrowed to one
// method where one is named.
function useQueueCounts(at: Scoped, enabled: boolean, method?: CodeFindingMethod) {
  const query = { limit: 1, ...(method ? { method } : {}) };
  return useQuery({
    enabled,
    queryKey: ["code-findings", at.product ?? "", { ...narrowing(at), method, limit: 1 }],
    queryFn: async (): Promise<CodeFindings> =>
      at.product
        ? unwrap(
            await api.GET("/v1/products/{product}/code-findings", {
              params: {
                path: { product: at.product },
                query: { ...query, ...codeFindingsQuery(narrowing(at)) },
              },
            }),
          )
        : unwrap(await api.GET("/v1/code-findings", { params: { query } })),
    retry: false,
  });
}

// The figures, at the picked scope.
export function SecurityTestingFigures({ who, code }: { who: Who; code: Holding }) {
  const at = useScope();
  const navigate = useNavigate();
  const products = codeProducts(who, at.product);
  const reads = products.length > 0;
  const one = at.product && reads ? at.product : undefined;
  const asked = narrowing(at);

  const queue = useQueueCounts(at, reads);
  const methods = Object.keys(CODE_FINDING_METHODS) as CodeFindingMethod[];
  // Split by method once there is more than one: each method's open count
  // from its own read, never one total over methods.
  const byMethod = useQueries({
    queries: (methods.length > 1 && reads ? methods : []).map((method) => ({
      queryKey: ["code-findings", at.product ?? "", { ...asked, method, limit: 1 }],
      queryFn: async (): Promise<CodeFindings> =>
        at.product
          ? unwrap(
              await api.GET("/v1/products/{product}/code-findings", {
                params: {
                  path: { product: at.product },
                  query: { limit: 1, method, ...codeFindingsQuery(asked) },
                },
              }),
            )
          : unwrap(await api.GET("/v1/code-findings", { params: { query: { limit: 1, method } } })),
      retry: false,
    })),
  });
  const trends = useQueries({
    queries: products.map((product) => ({
      queryKey: ["code-findings", product, "trend", { ...asked, weeks: WEEKS }],
      queryFn: async () =>
        unwrap(
          await api.GET("/v1/products/{product}/code-finding-trend", {
            params: { path: { product }, query: { weeks: WEEKS, ...codeFindingsQuery(asked) } },
          }),
        ),
      retry: false,
    })),
  });
  // The queue's oldest code finding, which the time to judge answers beside
  // its ages. Its window is the shortest, since only the queue is read here.
  const judging = useQueries({
    queries: products.map((product) => ({
      queryKey: ["code-findings", product, "time-to-judge", { ...asked, weeks: 1 }],
      queryFn: async () =>
        unwrap(
          await api.GET("/v1/products/{product}/code-finding-time-to-judge", {
            params: { path: { product }, query: { weeks: 1, ...codeFindingsQuery(asked) } },
          }),
        ),
      retry: false,
    })),
  });
  const coverages = useCoverages(products, at);

  if (!reads) return <HeldLine at={code} />;

  const counting = one
    ? [one, at.branch_or_tag, at.variant].filter(Boolean).join(" · ")
    : `${products.length.toLocaleString()} ${products.length === 1 ? "product" : "products"}`;
  const trend = merged(
    products,
    trends.map((each) => each.data),
    !one,
  );
  const series = coverages.flatMap((each, i) =>
    (each.data?.items ?? []).map((item) => ({ ...item, product: products[i] ?? "" })),
  );
  const quiet = series.filter((item) => item.quiet);
  const oldest = judging
    .map((each) => each.data?.oldest)
    .filter((when): when is string => !!when)
    .sort()[0];
  const last = trend?.points[trend.points.length - 1];
  const open = queue.data?.states?.open;
  const absent = queue.data?.states?.["no-longer-detected"];
  const queueAt = (state?: string) =>
    one
      ? codeFindingsAt(one, { state, ...asked })
      : codeFindingsAcrossAt(state ? { state } : undefined);

  const coverageRead = coverages.every((each) => each.isSuccess);
  if (coverageRead && series.length === 0) {
    return (
      <>
        <p className="eyebrow">Counting {counting}</p>
        <Empty
          title="No analyzer has run here."
          detail="Code findings arrive from analyzer runs uploaded against a build."
        />
      </>
    );
  }

  return (
    <>
      <div className="kpis">
        <button type="button" className="kpi" onClick={() => navigate(queueAt("open"))}>
          <span className="l">Open · {counting}</span>
          <span className="n">
            <Count of={queue}>{() => (open ?? 0).toLocaleString()}</Count>
          </span>
          <span className="d">
            {methods.length > 1
              ? methods
                  .map(
                    (method, i) =>
                      `${(byMethod[i]?.data?.states?.open ?? 0).toLocaleString()} ${CODE_FINDING_METHODS[method].label}`,
                  )
                  .join(" · ")
              : `to be judged, ${CODE_FINDING_METHODS[methods[0] ?? "sast"].hint.toLowerCase()}`}
          </span>
        </button>
        <button type="button" className="kpi" onClick={() => navigate(queueAt())}>
          <span className="l">
            <i style={{ background: "var(--wait)" }} /> Waiting for a judgment
          </span>
          <span className="n">
            <Count of={queue}>{() => (queue.data?.total ?? 0).toLocaleString()}</Count>
          </span>
          <span className="d">
            {judging.some((each) => each.isError)
              ? "nobody has proposed a decision"
              : oldest
                ? `nobody has proposed a decision · oldest ${ageOf(oldest)}`
                : "nobody has proposed a decision"}
          </span>
        </button>
        {/* Worked out from the trend, with nothing to open: the queue holds
            what is open, never what opened or was fixed in a week. One
            product's opens its page of code findings over time. */}
        <button
          type="button"
          className="kpi"
          disabled={!one}
          onClick={() => one && navigate(codeTrendAt())}
        >
          <span className="l">This week</span>
          <span className="n">
            <Count of={trends}>
              {() =>
                last ? `+${last.opened.toLocaleString()} −${last.fixed.toLocaleString()}` : "—"
              }
            </Count>
          </span>
          <span className="d">new, and fixed</span>
        </button>
        <button
          type="button"
          className="kpi"
          onClick={() => navigate(queueAt("no-longer-detected"))}
        >
          <span className="l">No longer detected</span>
          <span className="n">
            <Count of={queue}>{() => (absent ?? 0).toLocaleString()}</Count>
          </span>
          <span className="d">today, still counted until fixed</span>
        </button>
        <button
          type="button"
          className={`kpi${quiet.length > 0 ? " urgent" : ""}`}
          disabled={!one}
          onClick={() => one && navigate(analyticsReportAt("analysis-coverage"))}
        >
          <span className="l">Analyzers gone quiet</span>
          <span className="n">
            <Count of={coverages}>{() => quiet.length.toLocaleString()}</Count>
          </span>
          <span className="d">
            {quiet.length === 0
              ? "each within its own interval"
              : quiet
                  .slice(0, 2)
                  .map(
                    (item) =>
                      `${one ? "" : `${item.product} `}${item.series} on ${item.branch_or_tag_name || item.branch_or_tag} · ${item.variant_name || item.variant}`,
                  )
                  .join(", ") + (quiet.length > 2 ? ` and ${quiet.length - 2} more` : "")}
          </span>
        </button>
      </div>

      <div className="panels">
        <div className="panel wide">
          <header>
            <h3>Code findings over twelve weeks</h3>
            <span className="eyebrow" style={{ marginLeft: "auto" }}>
              not fixed, new and fixed · {counting}
            </span>
          </header>
          <Drawn trends={trends}>
            {() =>
              trend && (
                <>
                  <Pace
                    points={trend.points.map((point) => ({
                      at: point.at,
                      open: point.not_fixed,
                      opened: point.opened,
                      resolved: point.fixed,
                    }))}
                    words={WORDS}
                    marks={marksOf(trend)}
                  />
                  <div className="legend">
                    <span>
                      <i style={{ background: "var(--accent)" }} /> Not fixed
                    </span>
                    <span>
                      <i style={{ background: "var(--sev-high)" }} /> New
                    </span>
                    <span>
                      <i style={{ background: "var(--ok)" }} /> Fixed
                    </span>
                    {trend.markers.length > 0 && (
                      <span title="A tool, version or rule-set change, or a run that can't be compared">
                        <i style={{ background: "var(--faint)" }} /> Analyzer changed
                      </span>
                    )}
                  </div>
                  <p className="hint">Only fixing takes a code finding off the line.</p>
                </>
              )
            }
          </Drawn>
        </div>
        <div className="panel wide">
          <header>
            <h3>Not fixed by tier</h3>
            <span className="eyebrow" style={{ marginLeft: "auto" }}>
              rated now · {counting}
            </span>
          </header>
          <Drawn trends={trends}>
            {() =>
              trend && (
                <>
                  <Stack
                    rows={trend.points.map((point) => ({ at: point.at, ...point.by_tier }))}
                    parts={TIER_PARTS}
                  />
                  <div className="legend">
                    {TIER_PARTS.map((part) => (
                      <span key={part.key}>
                        <i style={{ background: part.color }} /> {part.label}
                      </span>
                    ))}
                  </div>
                </>
              )
            }
          </Drawn>
        </div>
      </div>
    </>
  );
}

const TIER_PARTS: StackPart[] = Object.entries(TIERS).map(([key, label], i) => ({
  key,
  label,
  color: TIER_COLORS[i] ?? "var(--muted)",
}));

// A chart's body once every product's trend is read: one failure stands for
// the whole, because a total missing a product is a wrong total.
function Drawn({
  trends,
  children,
}: {
  trends: UseQueryResult<CodeFindingTrend>[];
  children: () => React.ReactNode;
}) {
  const failed = trends.find((each) => each.isError);
  if (failed)
    return <Failed error={failed.error} what="The code findings over time could not be read." />;
  if (trends.some((each) => each.isPending)) return <Loading />;
  return <>{children()}</>;
}

// Every product's trend as one: the weeks end on the same days, so each
// week's counts add. A marker names its product where more than one is
// counted, because a series is one product's.
type Point = NonNullable<CodeFindingTrend["points"]>[number];
type Merged = { points: Point[]; markers: CodeFindingMarker[]; no_longer_detected: number };

export function merged(
  products: string[],
  trends: (CodeFindingTrend | undefined)[],
  named: boolean,
): Merged | undefined {
  if (trends.length === 0 || trends.some((each) => !each)) return undefined;
  const read = trends as CodeFindingTrend[];
  const first = read[0];
  if (!first) return undefined;
  const add = (a: Record<string, number>, b: Record<string, number>) => {
    const out = { ...a };
    for (const [key, n] of Object.entries(b)) out[key] = (out[key] ?? 0) + n;
    return out;
  };
  const points = (first.points ?? []).map((point, i) =>
    read.slice(1).reduce(
      (sum, other) => {
        const at = other.points?.[i];
        if (!at) return sum;
        return {
          at: sum.at,
          not_fixed: sum.not_fixed + at.not_fixed,
          opened: sum.opened + at.opened,
          fixed: sum.fixed + at.fixed,
          by_tier: add(sum.by_tier, at.by_tier),
          by_series: add(sum.by_series, at.by_series),
          by_method: add(sum.by_method, at.by_method),
        };
      },
      { ...point },
    ),
  );
  const markers: CodeFindingMarker[] = read.flatMap((trend, i) =>
    (trend.markers ?? []).map((m) =>
      named ? { ...m, series: `${products[i] ?? ""} ${m.series}` } : m,
    ),
  );
  return {
    points,
    markers: markers.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0)),
    no_longer_detected: read.reduce((sum, each) => sum + each.no_longer_detected, 0),
  };
}

// How long ago a day was, in days.
function ageOf(day: string): string {
  const days = Math.max(0, Math.floor((Date.now() - Date.parse(day)) / 86_400_000));
  return days === 1 ? "1 day" : `${days.toLocaleString()} days`;
}
