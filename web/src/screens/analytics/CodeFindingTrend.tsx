// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link, useSearchParams } from "react-router-dom";
import {
  useCodeFindingTrend,
  type CodeFindingMethod,
  type CodeFindingTrend as Trend,
} from "../../api/codeFindings";
import { codeFindingsAt } from "../../app/routes";
import { Pace, Stack, type StackPart } from "../../ui/Charts";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Wide } from "../../ui/Wide";
import { CODE_FINDING_METHODS } from "../codeFindings";
import {
  TIERS,
  marksOf,
  markerSaid,
  markersIn,
  partAt,
  partsOf,
  type TrendSplit,
} from "../codeTrend";
import { Sheet } from "./Sheet";
import {
  FIRST_DAYS,
  FIRST_WEEKS,
  MOST_DAYS,
  MOST_WEEKS,
  TrendWindow,
  boundedAsked,
  weeksWords,
  wordsFor,
} from "./Window";
import { Files, Gate, queryOf, useFigureAsked } from "./securityTesting";

// Whether the code findings backlog is shrinking: what is not fixed week by
// week, split by tier, series or method, what opened against what was fixed,
// and where an analyzer changed under the line.
//
// Code findings are security testing work, so a reader who does not read
// security testing material in the product is told so rather than shown a
// chart of zeros that reads as clean code. Never summed with the dependency
// backlog: a rule at a place and an advisory at a component are different
// units.

const SPLITS: { by: TrendSplit; words: string }[] = [
  { by: "tier", words: "Tier" },
  { by: "series", words: "Series" },
  { by: "method", words: "Method" },
];

// The tokens a split's parts are drawn in. Tiers are a ranking, so they take
// the severity ladder's; series and methods take the rest in turn.
const TIER_COLORS = [
  "var(--sev-critical)",
  "var(--sev-high)",
  "var(--sev-medium)",
  "var(--sev-low)",
];
const TURN = [
  "var(--accent)",
  "var(--sev-high)",
  "var(--ok)",
  "var(--sev-medium)",
  "var(--wait)",
  "var(--sev-low)",
  "var(--muted)",
];

function partsDrawn(trend: Trend, by: TrendSplit): StackPart[] {
  return partsOf(trend, by).map((key, i) => ({
    key,
    label:
      by === "tier"
        ? (TIERS[key] ?? key)
        : by === "method"
          ? (CODE_FINDING_METHODS[key as CodeFindingMethod]?.label ?? key)
          : key,
    color: by === "tier" ? (TIER_COLORS[i] ?? "var(--muted)") : (TURN[i % TURN.length] ?? ""),
  }));
}

export function CodeFindingTrend() {
  const { product, asked: narrowed, code, reads, needsBuild, of, params } = useFigureAsked();
  const [, setParams] = useSearchParams();
  // Daily unless the address says weekly, as the backlog sheet is.
  const daily = params.get("step") !== "week";
  const weeks = boundedAsked(params.get("weeks"), MOST_WEEKS, FIRST_WEEKS);
  const days = boundedAsked(params.get("days"), MOST_DAYS, FIRST_DAYS);
  const by: TrendSplit =
    SPLITS.find((each) => each.by === params.get("by"))?.by ?? ("tier" as TrendSplit);
  const asked = daily ? { ...narrowed, weeks: undefined, days } : { ...narrowed, weeks };
  const trend = useCodeFindingTrend(product, asked, !!product && reads && !needsBuild);

  const choose = (next: TrendSplit) => {
    const out = new URLSearchParams(params);
    if (next === "tier") out.delete("by");
    else out.set("by", next);
    setParams(out, { replace: true });
  };

  return (
    <Sheet
      settled={!product || !reads || needsBuild || trend.isSuccess}
      name="Code findings over time"
      answers="whether the code findings backlog is shrinking, and where an analyzer change moved it."
      of={of}
      asked={`${daily ? wordsFor(days) : weeksWords(weeks)}, by ${by}`}
    >
      <div className="controls">
        <TrendWindow daily={daily} days={days} weeks={weeks} />
        <div className="seg" role="group" aria-label="Split by">
          {SPLITS.map((each) => (
            <button
              key={each.by}
              type="button"
              aria-pressed={by === each.by}
              onClick={() => choose(each.by)}
            >
              {each.words}
            </button>
          ))}
        </div>
        {product && reads && !needsBuild && (
          <Files
            path="/v1/products/{product}/code-finding-trend.{format}"
            product={product}
            query={queryOf(asked)}
          />
        )}
      </div>

      <Gate product={product} code={code} needsBuild={needsBuild}>
        {trend.isPending ? (
          <Loading />
        ) : trend.isError ? (
          <Failed error={trend.error} what="The code findings over time could not be read." />
        ) : (
          <Drawn
            trend={trend.data}
            by={by}
            product={product}
            narrowed={narrowed}
            unit={daily ? "days" : "weeks"}
          />
        )}
      </Gate>
    </Sheet>
  );
}

function Drawn({
  trend,
  by,
  product,
  narrowed,
  unit,
}: {
  trend: Trend;
  by: TrendSplit;
  product: string;
  narrowed: NonNullable<Parameters<typeof codeFindingsAt>[1]>;
  unit: string;
}) {
  const points = trend.points ?? [];
  const paced = points.map((each) => ({
    at: each.at,
    open: each.not_fixed,
    new: each.opened,
    corrected: each.fixed,
  }));
  const parts = partsDrawn(trend, by);
  const split = points.map((point) => ({
    at: point.at,
    ...Object.fromEntries(parts.map((part) => [part.key, partAt(point, by, part.key)])),
  }));
  const markers = trend.markers ?? [];
  const absent = trend.no_longer_detected;

  if (!points.some((p) => p.not_fixed > 0 || p.opened > 0 || p.fixed > 0)) {
    return (
      <section className="panel">
        <Empty
          title="No code finding in these steps."
          detail="Nothing was open here, and no run opened anything."
        />
      </section>
    );
  }

  return (
    <>
      <section className="panel">
        <h3>Not fixed, new and fixed</h3>
        <Pace points={paced} words={WORDS} marks={marksOf(trend)} unit={unit} />
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
          {markers.length > 0 && (
            <span title="A tool, version or rule-set change, or a run that can't be compared">
              <i style={{ background: "var(--faint)" }} /> Analyzer changed
            </span>
          )}
        </div>
        <p className="hint">
          Counted once per code finding, by when its run was applied. Only fixing takes one off the
          line.
        </p>
        <p className="hint">
          {absent === 0 ? (
            "None is no longer detected now."
          ) : (
            <>
              <Link to={codeFindingsAt(product, { ...narrowed, state: "no-longer-detected" })}>
                {absent.toLocaleString()} no longer detected
              </Link>{" "}
              now, still counted as not fixed: a run stopped seeing {absent === 1 ? "it" : "them"},
              which fixes nothing.
            </>
          )}
        </p>
      </section>

      <section className="panel">
        <h3>Not fixed by {by}</h3>
        {parts.length === 0 ? (
          <Empty title="No code finding in these steps." />
        ) : (
          <>
            <Stack rows={split} parts={parts} />
            <div className="legend">
              {parts.map((part) => (
                <span key={part.key}>
                  <i style={{ background: part.color }} /> {part.label}
                </span>
              ))}
            </div>
          </>
        )}
        {by === "tier" && (
          <p className="hint">The tier is the rule&rsquo;s weaknesses as rated now.</p>
        )}
      </section>

      <section className="panel">
        <h3>{unit === "days" ? "Day by day" : "Week by week"}</h3>
        <Wide>
          <table>
            <thead>
              <tr>
                <th>{unit === "days" ? "Day" : "Week ending"}</th>
                <th className="num">Not fixed</th>
                <th className="num">New</th>
                <th className="num">Fixed</th>
                {parts.map((part) => (
                  <th key={part.key} className="num">
                    {part.label}
                  </th>
                ))}
                <th>Analyzer changes</th>
              </tr>
            </thead>
            <tbody>
              {points.map((point, i) => (
                <tr key={point.at}>
                  <td className="id">{point.at}</td>
                  <td className="num">{point.not_fixed.toLocaleString()}</td>
                  {/* The first step has nothing to differ from. */}
                  <td className="num">{i === 0 ? "—" : point.opened.toLocaleString()}</td>
                  <td className="num">{i === 0 ? "—" : point.fixed.toLocaleString()}</td>
                  {parts.map((part) => (
                    <td key={part.key} className="num hint">
                      {partAt(point, by, part.key).toLocaleString()}
                    </td>
                  ))}
                  <td className="hint">
                    {markersIn(trend, i)
                      .map((m) => markerSaid(m))
                      .join("; ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      </section>
    </>
  );
}

const WORDS = {
  line: "not fixed",
  what: "Code findings not fixed",
  fresh: "new code findings",
  back: "returned",
  done: "fixed",
};
