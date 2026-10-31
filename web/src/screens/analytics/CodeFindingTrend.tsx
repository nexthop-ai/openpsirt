// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link, useSearchParams } from "react-router-dom";
import {
  useCodeFindingTrend,
  type CodeFindingMethod,
  type CodeFindingTrend as Trend,
} from "../../api/codeFindings";
import { fileAt } from "../../api/links";
import { counted, heldLine, holding } from "../../app/families";
import { codeFindingsAt } from "../../app/routes";
import { askForScope, useScope } from "../../app/scope";
import { useWho } from "../../app/session";
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
import { scopeWords } from "./catalog";
import { Sheet } from "./Sheet";
import { Segments, boundedAsked } from "./Window";

// Whether the code findings backlog is shrinking: what is not fixed week by
// week, split by tier, series or method, what opened against what was fixed,
// and where an analyzer changed under the line.
//
// Code findings are security testing work, so a reader who does not read
// security testing material in the product is told so rather than shown a
// chart of zeros that reads as clean code. Never summed with the dependency
// backlog: a rule at a place and an advisory at a component are different
// units.

// The windows offered, as the backlog offers them.
const WEEKS = [4, 13, 26, 52, 104] as const;

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
  const at = useScope();
  const product = at.product ?? "";
  const [params, setParams] = useSearchParams();
  const weeks = boundedAsked(params.get("weeks"), 104, 13);
  const by: TrendSplit =
    SPLITS.find((each) => each.by === params.get("by"))?.by ?? ("tier" as TrendSplit);
  const method = (params.get("method") ?? undefined) as CodeFindingMethod | undefined;
  const narrowed = {
    series: params.get("series") ?? undefined,
    method,
    component: params.get("component") ?? undefined,
    component_version: params.get("component_version") ?? undefined,
    beneath: params.get("beneath") ?? undefined,
    beneath_version: params.get("beneath_version") ?? undefined,
    beneath_ecosystem: params.get("beneath_ecosystem") ?? undefined,
    beneath_namespace: params.get("beneath_namespace") ?? undefined,
  };
  // A branch and a variant the address names stand over the picker's, so a
  // link from a queue opens on the builds it lists; one named empty is every
  // one, as a queue over every build sends it.
  const branchOrTag = params.get("branch_or_tag") ?? at.branch_or_tag;
  const variant = params.get("variant") ?? at.variant;
  const asked = {
    branch_or_tag: branchOrTag,
    variant,
    ...narrowed,
    weeks,
  };

  const code = holding(useWho().data, "code", product || undefined);
  const reads = counted(code);
  // At or under a component is read on one build.
  const needsBuild = !!narrowed.beneath && !(branchOrTag && variant);
  const trend = useCodeFindingTrend(product, asked, !!product && reads && !needsBuild);

  const query = new URLSearchParams(
    Object.entries({ ...asked, weeks: String(weeks) }).filter(
      (entry): entry is [string, string] => !!entry[1],
    ),
  ).toString();
  const file = (format: "csv" | "json") =>
    fileAt("/v1/products/{product}/code-finding-trend.{format}", format, {
      path: { product },
      query,
    });
  const choose = (next: TrendSplit) => {
    const out = new URLSearchParams(params);
    if (next === "tier") out.delete("by");
    else out.set("by", next);
    setParams(out, { replace: true });
  };

  const of = [
    scopeWords({
      product: at.product,
      branch_or_tag: branchOrTag || undefined,
      variant: variant || undefined,
    }),
    narrowed.series,
    method && CODE_FINDING_METHODS[method]?.label,
    narrowed.component && `on ${narrowed.component}`,
    narrowed.beneath && `at or under ${narrowed.beneath}`,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <Sheet
      settled={!product || !reads || needsBuild || trend.isSuccess}
      name="Code findings over time"
      answers="whether the code findings backlog is shrinking, and where an analyzer change moved it."
      of={of}
      asked={`${weeks} weeks, by ${by}`}
    >
      <div className="controls">
        <Segments
          label="Window"
          param="weeks"
          offered={WEEKS}
          chosen={weeks}
          words={(n) => (n === 104 ? "two years" : n === 52 ? "a year" : `${n} weeks`)}
        />
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
          <span style={{ marginLeft: "auto" }} className="noprint">
            <a className="btn quiet" href={file("csv")}>
              CSV
            </a>{" "}
            <a className="btn quiet" href={file("json")}>
              JSON
            </a>
          </span>
        )}
      </div>

      {product === "" ? (
        <section className="panel">
          <Empty title="Pick a product." detail="Code findings are counted per product." />
        </section>
      ) : !reads ? (
        <section className="panel">
          <Empty title="Nothing to list." detail={heldLine(code)} />
        </section>
      ) : needsBuild ? (
        <section className="panel">
          <Empty
            title="This needs one build."
            detail="At or under a component is read on one build. Pick a branch and a variant."
          >
            <button type="button" className="btn" onClick={askForScope}>
              Pick a build
            </button>
          </Empty>
        </section>
      ) : trend.isPending ? (
        <Loading />
      ) : trend.isError ? (
        <Failed error={trend.error} what="The code findings over time could not be read." />
      ) : (
        <Drawn
          trend={trend.data}
          by={by}
          product={product}
          narrowed={{ branch_or_tag: branchOrTag, variant, ...narrowed }}
        />
      )}
    </Sheet>
  );
}

function Drawn({
  trend,
  by,
  product,
  narrowed,
}: {
  trend: Trend;
  by: TrendSplit;
  product: string;
  narrowed: NonNullable<Parameters<typeof codeFindingsAt>[1]>;
}) {
  const points = trend.points ?? [];
  const paced = points.map((each) => ({
    at: each.at,
    open: each.not_fixed,
    opened: each.opened,
    resolved: each.fixed,
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
          title="No code finding in these weeks."
          detail="Nothing was open here, and no run opened anything."
        />
      </section>
    );
  }

  return (
    <>
      <section className="panel">
        <h3>Not fixed, new and fixed</h3>
        <Pace points={paced} words={WORDS} marks={marksOf(trend)} />
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
          <Empty title="No series has a code finding in these weeks." />
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
        <h3>Week by week</h3>
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Week ending</th>
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
                  {/* The first week has nothing to differ from. */}
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
  done: "fixed",
};
