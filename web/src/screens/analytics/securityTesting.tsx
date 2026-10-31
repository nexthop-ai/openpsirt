// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import {
  codeFindingsQuery,
  type CodeFindingFigureAsked,
  type CodeFindingMethod,
  type CodeFindingWaits,
} from "../../api/codeFindings";
import { fileAt } from "../../api/links";
import { counted, heldLine, holding, type Holding } from "../../app/families";
import { askForScope, useScope } from "../../app/scope";
import { useWho } from "../../app/session";
import { Empty } from "../../ui/Empty";
import { Wide } from "../../ui/Wide";
import { CODE_FINDING_METHODS } from "../codeFindings";
import { TIERS } from "../codeTrend";
import { scopeWords } from "./catalog";

// What the security testing figures share: the narrowing they read from the
// address and the picker, the frame they draw in place of figures a reader
// does not hold, their files, and how a set of waits is drawn.
//
// Every figure is counted per testing method and never beside a dependency
// figure; a reader who does not read security testing material in the
// product is told so in one line rather than shown zeros.

// The windows offered, as the trend offers them.
export const WEEKS = [4, 13, 26, 52, 104] as const;

export function weeksWords(n: number): string {
  return n === 104 ? "two years" : n === 52 ? "a year" : `${n} weeks`;
}

// The narrowing in the address, over the picker's scope. A branch and a
// variant the address names stand over the picker's, so a link from a queue
// opens on the builds it lists; one named empty is every one. A branchless
// figure reads every branch and tag, and its heading names none.
export function useFigureAsked({ branchless = false }: { branchless?: boolean } = {}) {
  const at = useScope();
  const [params] = useSearchParams();
  const product = at.product ?? "";
  const method = (params.get("method") ?? undefined) as CodeFindingMethod | undefined;
  const asked: CodeFindingFigureAsked = {
    branch_or_tag: params.get("branch_or_tag") ?? at.branch_or_tag,
    variant: params.get("variant") ?? at.variant,
    series: params.get("series") ?? undefined,
    method,
    component: params.get("component") ?? undefined,
    component_version: params.get("component_version") ?? undefined,
    beneath: params.get("beneath") ?? undefined,
    beneath_version: params.get("beneath_version") ?? undefined,
    beneath_ecosystem: params.get("beneath_ecosystem") ?? undefined,
    beneath_namespace: params.get("beneath_namespace") ?? undefined,
  };
  const code = holding(useWho().data, "code", product || undefined);
  // At or under a component is read on one build.
  const needsBuild = !!asked.beneath && !(asked.branch_or_tag && asked.variant);
  const of = [
    scopeWords({
      product: at.product,
      branch_or_tag: branchless ? undefined : asked.branch_or_tag || undefined,
      variant: asked.variant || undefined,
    }),
    asked.series,
    method && CODE_FINDING_METHODS[method]?.label,
    asked.component && `on ${asked.component}`,
    asked.beneath && `at or under ${asked.beneath}`,
  ]
    .filter(Boolean)
    .join(" · ");
  return { product, asked, code, reads: counted(code), needsBuild, of, params };
}

// The query a figure's file is asked with: the query its page asks, so the
// file and the screen read the same narrowing.
export function queryOf(asked: Record<string, string | number | undefined>): string {
  return new URLSearchParams(
    Object.entries(codeFindingsQuery(asked)).map(([key, value]) => [key, String(value)]),
  ).toString();
}

type FigureFile =
  | "/v1/products/{product}/code-finding-time-to-judge.{format}"
  | "/v1/products/{product}/code-finding-time-to-fix.{format}"
  | "/v1/products/{product}/code-finding-precision.{format}"
  | "/v1/products/{product}/analysis-coverage.{format}"
  | "/v1/products/{product}/code-findings-by-release.{format}";

// The figure's file as CSV and JSON, with the narrowing on screen.
export function Files({
  path,
  product,
  query,
}: {
  path: FigureFile;
  product: string;
  query: string;
}) {
  const file = (format: "csv" | "json") => fileAt(path, format, { path: { product }, query });
  return (
    <span style={{ marginLeft: "auto" }} className="noprint">
      <a className="btn quiet" href={file("csv")}>
        CSV
      </a>{" "}
      <a className="btn quiet" href={file("json")}>
        JSON
      </a>
    </span>
  );
}

// What a figure draws in place of its body: a product to pick, the line for a
// family the reader does not read here, or a build to pick for a subtree.
export function Gate({
  product,
  code,
  needsBuild,
  children,
}: {
  product: string;
  code: Holding;
  needsBuild?: boolean;
  children: ReactNode;
}) {
  if (product === "") {
    return (
      <section className="panel">
        <Empty title="Pick a product." detail="Code findings are counted per product." />
      </section>
    );
  }
  if (!counted(code)) {
    return (
      <section className="panel">
        <Empty title="Nothing to list." detail={heldLine(code)} />
      </section>
    );
  }
  if (needsBuild) {
    return (
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
    );
  }
  return <>{children}</>;
}

// Days to a tenth, as the server rounds them.
export function inDays(days: number): string {
  return days === 1 ? "1 day" : `${days.toLocaleString()} days`;
}

// A set of waits: the whole set, then each tier, with how many it is over.
export function WaitsTable({ waits, none }: { waits: CodeFindingWaits; none: string }) {
  const rows = [{ label: "All tiers", wait: waits.all }].concat(
    (waits.by_tier ?? []).map((wait) => ({
      label: TIERS[wait.tier ?? ""] ?? wait.tier ?? "",
      wait,
    })),
  );
  if (waits.all.count === 0) return <Empty title={none} />;
  return (
    <Wide>
      <table>
        <thead>
          <tr>
            <th>Tier</th>
            <th className="num">Code findings</th>
            <th className="num">Median</th>
            <th className="num">90th percentile</th>
            <th className="num">Longest</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ label, wait }) => (
            <tr key={label}>
              <td>{label}</td>
              <td className="num">{wait.count.toLocaleString()}</td>
              <td className="num">{wait.count === 0 ? "—" : inDays(wait.median_days)}</td>
              <td className="num">{wait.count === 0 ? "—" : inDays(wait.p90_days)}</td>
              <td className="num">{wait.count === 0 ? "—" : inDays(wait.worst_days)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Wide>
  );
}
