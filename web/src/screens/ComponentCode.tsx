// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import type { Holding } from "../app/families";
import { codeFindingsAt, repositoriesAt } from "../app/routes";
import {
  useComponentCodeCounts,
  useComponentCodeTrend,
  type CodeFindingState,
  type ComponentCodeCounts,
} from "../api/codeFindings";
import { Failed } from "../ui/Failed";
import { HeldLine } from "../ui/HeldLine";
import { Loading } from "../ui/Loading";
import { Pace, TREND_WEEKS, trendSaid } from "../ui/Charts";
import { Wide } from "../ui/Wide";
import { CODE_FINDING_STATES } from "./codeFindings";

// The security testing half of the component screen: what the analyzers hold
// on the source package, per series and state, and over twelve weeks on one
// build. Drawn beside the dependency counts and never added to them, because a
// rule at a place and an advisory at a component are different units.

// The columns, in the order a code finding meets them: what is worked first,
// then what has been answered.
const COLUMNS: CodeFindingState[] = [
  "open",
  "no-longer-detected",
  "dismissed",
  "not-security",
  "confirmed",
  "recorded-as-flaw",
  "fixed",
];

type Which = { version?: string; ecosystem?: string; namespace?: string };

// The open code findings each build places on the source package at a
// version, keyed as the build rows are, for their column.
export function codeByBuild(counts?: ComponentCodeCounts): Map<string, number> {
  const out = new Map<string, number>();
  for (const each of counts?.builds ?? []) {
    out.set(buildCodeKey(each.branch_or_tag, each.variant, each.version), each.open);
  }
  return out;
}

const buildCodeKey = (branchOrTag = "", variant = "", version = "") =>
  [branchOrTag, variant, version].join("\u001e");

// One build row's open code findings on the source package at the row's
// version, opening the queue at that build and version. A zero opens nothing.
export function BuildCodeCell({
  product,
  row,
  code,
}: {
  product: string;
  row: { source?: string; version?: string; branch_or_tag?: string; variant?: string };
  code: Map<string, number>;
}) {
  const open = code.get(buildCodeKey(row.branch_or_tag, row.variant, row.version)) ?? 0;
  return (
    <td className="num">
      {open > 0 ? (
        <Link
          to={codeFindingsAt(product, {
            component: row.source,
            component_version: row.version,
            branch_or_tag: row.branch_or_tag,
            variant: row.variant,
            state: "open",
          })}
        >
          {open.toLocaleString()}
        </Link>
      ) : (
        <span className="hint">0</span>
      )}
    </td>
  );
}

// The card: one row per analyzer series, a count per state, each opening the
// queue narrowed to the source package, that series and that state.
export function SecurityTesting({
  product,
  source,
  code,
  counts,
}: {
  product: string;
  source: string;
  code: Holding;
  counts: ReturnType<typeof useComponentCodeCounts>;
}) {
  if (code.held === "nowhere") return null;
  if (code.held === "elsewhere") {
    return (
      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Security testing</h3>
        <HeldLine at={code} />
      </div>
    );
  }
  const series = counts.data?.series ?? [];
  const open = series.reduce((sum, each) => sum + (each.states.open ?? 0), 0);
  const unplaced = series.reduce((sum, each) => sum + each.unplaced, 0);
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="screen-head" style={{ marginBottom: 8 }}>
        <h3>Security testing</h3>
        {counts.data && (
          <Link
            className="eyebrow"
            style={{ marginLeft: "auto" }}
            to={codeFindingsAt(product, { component: source, state: "open" })}
            title="Open code findings on this source package, across every build"
          >
            {open.toLocaleString()} {open === 1 ? "code finding" : "code findings"} open
          </Link>
        )}
      </div>
      <HeldLine at={code} />
      {counts.isPending ? (
        <Loading />
      ) : counts.isError ? (
        <Failed error={counts.error} what="The code findings could not be counted." />
      ) : series.length === 0 ? (
        <p className="hint">No analyzer has sent results for this product.</p>
      ) : (
        <>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Series</th>
                  {COLUMNS.map((state) => (
                    <th key={state} className="num">
                      {CODE_FINDING_STATES[state]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {series.map((row) => (
                  <tr key={row.series}>
                    <td className="id">{row.series}</td>
                    {COLUMNS.map((state) => {
                      const n = row.states[state] ?? 0;
                      return (
                        <td key={state} className="num">
                          {n > 0 ? (
                            <Link
                              to={codeFindingsAt(product, {
                                component: source,
                                series: row.series,
                                state,
                              })}
                            >
                              {n.toLocaleString()}
                            </Link>
                          ) : (
                            <span className="hint">0</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
          <p className="hint" style={{ marginTop: 8 }}>
            Every build of the product. A code finding on two builds in two states counts in both.
          </p>
          {unplaced > 0 && (
            <p className="hint" title="In files no repository this build is built from holds">
              {unplaced.toLocaleString()} of those open {unplaced === 1 ? "is" : "are"} unplaced, on
              the build itself. <Link to={repositoriesAt(product)}>Repositories →</Link>
            </p>
          )}
        </>
      )}
    </div>
  );
}

// Twelve weeks of code findings at the package and under it on one build: a
// panel of its own beside the dependency one, never a summed line.
export function CodeHistory({
  product,
  build,
  component,
  which,
}: {
  product: string;
  build: { branch_or_tag?: string; variant?: string };
  component: string;
  which: Which;
}) {
  const at = {
    product,
    branch_or_tag: build.branch_or_tag ?? "",
    variant: build.variant ?? "",
  };
  const trend = useComponentCodeTrend(at, component, which, TREND_WEEKS);
  const points = (trend.data ?? []).map((each) => ({
    at: each.at,
    open: each.not_fixed,
    opened: each.opened,
    resolved: each.fixed,
  }));
  const moved = points.some((each) => each.open > 0 || each.opened > 0 || each.resolved > 0);
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="screen-head" style={{ marginBottom: 8 }}>
        <h3>Code findings · {trendSaid}</h3>
        <span className="eyebrow" style={{ marginLeft: "auto" }}>
          {at.branch_or_tag} · {at.variant}
        </span>
      </div>
      {trend.isError ? (
        <p className="hint">Could not be read.</p>
      ) : trend.isPending ? (
        <Loading />
      ) : !moved ? (
        <p className="hint">No code finding here in {trendSaid}.</p>
      ) : (
        <Pace points={points} words={CODE_WORDS} />
      )}
    </div>
  );
}

const CODE_WORDS = {
  line: "not fixed",
  what: "Code findings not fixed",
  fresh: "new code findings",
  done: "fixed",
};
