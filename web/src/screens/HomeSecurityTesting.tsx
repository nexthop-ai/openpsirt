// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQueries, useQuery, type UseQueryResult } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  analysisCoverageAcrossRead,
  analysisCoverageRead,
  codeFindingCountsRead,
  codeFindingJudgingAcrossRead,
  codeFindingJudgingRead,
  codeFindingTrendAcrossRead,
  codeFindingTrendRead,
  type AnalysisCoverage,
  type CodeFindingMarker,
  type CodeFindingMethod,
  type CodeFindingTrend,
} from "../api/codeFindings";
import { statusOf } from "../api/queries";
import { counted, holding, refusedAt, type Holding } from "../app/families";
import { analyticsReportAt, codeFindingsAcrossAt, codeFindingsAt } from "../app/routes";
import { useScope, type Scoped } from "../app/scope";
import type { Who } from "../app/session";
import { Pace, Stack, type StackPart } from "../ui/Charts";
import { Count, type Readable } from "../ui/Count";
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
// Every figure is one read: of the product picked, or with none picked one
// read across every product in use where the reader reads security testing
// material, the products the session lists them as reading it in, and the
// head says how many. The server adds the products together.

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

// The product a figure is asked of, the one picked; none is the read across
// products.
function pickedOf(products: string[], at: Scoped): string | undefined {
  return at.product && products.length > 0 ? at.product : undefined;
}

// The analysis coverage, for the quiet series and the newest run: one read of
// the product picked, or one across products. Shared with the status panel,
// which asks the same read. Nothing is asked where no product is counted.
export function useCoverages(products: string[], at: Scoped): UseQueryResult<AnalysisCoverage>[] {
  const one = pickedOf(products, at);
  const read = one
    ? analysisCoverageRead(one, { ...narrowing(at), weeks: COVERAGE_WEEKS })
    : analysisCoverageAcrossRead({ weeks: COVERAGE_WEEKS });
  const queries: (typeof read)[] = products.length === 0 ? [] : [read];
  return useQueries({ queries });
}

// The holding a product's refused read says: a product the session does not
// list is held here until the server refuses a read of it.
export function heldAfter(code: Holding, reads: Readable[], product: string | undefined): Holding {
  if (!product) return code;
  const refusal = reads.find((each) => statusOf(each.error) === 403);
  return refusal ? refusedAt(code, refusal.error, product) : code;
}

// The queue's counts, narrowed to the picker and to one method where one is
// named.
function queueRead(one: string | undefined, at: Scoped, method?: CodeFindingMethod) {
  return codeFindingCountsRead(one, { ...narrowing(at), method });
}

// The figures, at the picked scope.
export function SecurityTestingFigures({ who, code }: { who: Who; code: Holding }) {
  const at = useScope();
  const navigate = useNavigate();
  const products = codeProducts(who, at.product);
  const reads = products.length > 0;
  const one = pickedOf(products, at);
  const asked = narrowing(at);

  const queue = useQuery({ ...queueRead(one, at), enabled: reads });
  const methods = Object.keys(CODE_FINDING_METHODS) as CodeFindingMethod[];
  // Split by method once there is more than one: each method's open count
  // from its own read, never one total over methods.
  const split = methods.length > 1 && reads;
  const byMethod = useQueries({
    queries: (split ? methods : []).map((method) => queueRead(one, at, method)),
  });
  const trends = useQuery({
    ...(one
      ? codeFindingTrendRead(one, { ...asked, weeks: WEEKS })
      : codeFindingTrendAcrossRead({ weeks: WEEKS })),
    enabled: reads,
  });
  // The queue's oldest code finding, which the time to judge answers beside
  // its ages. Its window is the shortest, since only the queue is read here.
  const judging = useQuery({
    ...(one
      ? codeFindingJudgingRead(one, { ...asked, weeks: 1 })
      : codeFindingJudgingAcrossRead({ weeks: 1 })),
    enabled: reads,
  });
  const coverages = useCoverages(products, at);

  const held = heldAfter(code, [queue, trends, judging, ...coverages], one);
  if (!reads || !counted(held)) return <HeldLine at={held} />;

  const counting = one
    ? [one, at.branch_or_tag, at.variant].filter(Boolean).join(" · ")
    : `${products.length.toLocaleString()} ${products.length === 1 ? "product" : "products"}`;
  const trend = trends.data && named(trends.data, !one);
  const series = coverages.flatMap((each) => each.data?.items ?? []);
  const quiet = series.filter((item) => item.quiet);
  const oldest = judging.data?.oldest;
  const last = trend?.points[trend.points.length - 1];
  const open = queue.data?.states?.open ?? 0;
  const absent = queue.data?.states?.["no-longer-detected"] ?? 0;
  const waiting = queue.data?.total ?? 0;
  const queueAt = (state?: string) =>
    one
      ? codeFindingsAt(one, { state, ...asked })
      : codeFindingsAcrossAt(state ? { state } : undefined);

  // No series and nothing in the queue: a code finding outlives its series in
  // the coverage, which leaves out a retired branch or variant.
  const coverageRead = coverages.every((each) => each.isSuccess);
  const queueAnswered = queue.isSuccess;
  const queued =
    (queue.data?.total ?? 0) > 0 ||
    Object.values(queue.data?.states ?? {}).some((n) => (n ?? 0) > 0);
  if (coverageRead && queueAnswered && series.length === 0 && !queued) {
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
            <Count of={queue}>{() => open.toLocaleString()}</Count>
          </span>
          <span className="d">
            {split
              ? methods.map((method, i) => (
                  <span key={method}>
                    {i > 0 && " · "}
                    <Count of={byMethod[i] ?? []}>
                      {() => (byMethod[i]?.data?.states?.open ?? 0).toLocaleString()}
                    </Count>{" "}
                    {CODE_FINDING_METHODS[method].label}
                  </span>
                ))
              : `to be judged, ${CODE_FINDING_METHODS[methods[0] ?? "sast"].hint.toLowerCase()}`}
          </span>
        </button>
        <button type="button" className="kpi" onClick={() => navigate(queueAt())}>
          <span className="l">
            <i style={{ background: "var(--wait)" }} /> Waiting for a judgment
          </span>
          <span className="n">
            <Count of={queue}>{() => waiting.toLocaleString()}</Count>
          </span>
          <span className="d">
            nobody has proposed a decision
            <Count of={judging}>{() => (oldest ? ` · oldest ${ageOf(oldest)}` : "")}</Count>
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
            <Count of={queue}>{() => absent.toLocaleString()}</Count>
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

// A chart's body once the trend is read.
function Drawn({
  trends,
  children,
}: {
  trends: UseQueryResult<CodeFindingTrend>;
  children: () => React.ReactNode;
}) {
  if (trends.isError)
    return <Failed error={trends.error} what="The code findings over time could not be read." />;
  if (trends.isPending) return <Loading />;
  return <>{children()}</>;
}

// A trend as the charts draw it, each marker naming its product where the
// trend is across products, because a series is one product's.
type Point = NonNullable<CodeFindingTrend["points"]>[number];
type Drawable = { points: Point[]; markers: CodeFindingMarker[]; no_longer_detected: number };

function named(trend: CodeFindingTrend, across: boolean): Drawable {
  const markers = trend.markers ?? [];
  return {
    points: trend.points ?? [],
    no_longer_detected: trend.no_longer_detected,
    markers: across ? markers.map((m) => ({ ...m, series: `${m.product} ${m.series}` })) : markers,
  };
}

// How long ago a day was, in days.
function ageOf(day: string): string {
  const days = Math.max(0, Math.floor((Date.now() - Date.parse(day)) / 86_400_000));
  return days === 1 ? "1 day" : `${days.toLocaleString()} days`;
}
