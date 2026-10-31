// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { CodeFindingMarker, CodeFindingTrend } from "../api/codeFindings";
import { analyticsReportAt } from "../app/routes";
import type { PaceMark } from "../ui/Charts";

// The address of the Code findings over time page under the catalog.
const CODE_TREND = "code-findings-over-time";

// The page with a narrowing carried, as the queue and a component name one.
// A branch and a variant named here stand over the picker's, an empty one
// meaning every one; one left out leaves the picker's.
export function codeTrendAt(query: Record<string, string | undefined> = {}): string {
  return analyticsReportAt(CODE_TREND, query);
}

// What a trend of code findings is split by, as the server names each part.
export type TrendSplit = "tier" | "series" | "method";

// The tiers of a rule's weaknesses, highest first, as the queue orders them.
// eslint-disable-next-line no-restricted-syntax -- Keyed on the server's tier names.
export const TIERS: Record<string, string> = {
  "memory-safety": "Memory safety",
  input: "Input reaching where it shouldn't",
  resource: "Resource or error unhandled",
  other: "Everything else",
};

// Why a run's absences prove nothing, in a few words.
// eslint-disable-next-line no-restricted-syntax -- Keyed on the server's reasons.
export const REASONS: Record<string, string> = {
  "exit-status": "exited with an error",
  incomplete: "didn't finish",
  "failure-signal": "reported a failure of its own",
  "no-coverage": "stated no coverage",
  "units-short": "analyzed fewer units than expected",
  "tool-changed": "a new tool or version",
  "rules-changed": "a new rule set",
};

// What a marker names where a run stated no tool, version or rule count.
const NOT_STATED = "not stated";

// One marker as a line: which series, what moved, and on how many builds.
export function markerSaid(m: CodeFindingMarker): string {
  const builds = m.builds === 1 ? "" : ` (${m.builds.toLocaleString()} builds)`;
  const side = (value: string | undefined, unit: string) =>
    value ? `${value}${unit}` : NOT_STATED;
  const between = (unit = "") =>
    m.from || m.to ? ` from ${side(m.from, unit)} to ${side(m.to, unit)}` : "";
  switch (m.change) {
    case "tool":
      return `${m.series}: tool changed${between()}${builds}`;
    case "tool-version":
      return `${m.series}: new version${between()}${builds}`;
    case "rules":
      return `${m.series}: rule set changed${between(" rules")}${builds}`;
    case "not-comparable":
      return `${m.series}: not comparable, ${REASONS[m.reason ?? ""] ?? "for another reason"}${builds}`;
  }
}

type Point = NonNullable<CodeFindingTrend["points"]>[number];

// The week a marker falls in: the first whose last day is its day or after.
// A marker is dated by day, and so is a week's end.
function stepOf(points: Point[], at: string): number {
  return points.findIndex((p) => p.at >= at);
}

// The marks a pace chart draws: one per week with any marker, saying each.
export function marksOf(trend: CodeFindingTrend | undefined): PaceMark[] {
  const points = trend?.points ?? [];
  const said = new Map<number, string[]>();
  for (const m of trend?.markers ?? []) {
    const step = stepOf(points, m.at);
    if (step < 0) continue;
    said.set(step, [...(said.get(step) ?? []), markerSaid(m)]);
  }
  return [...said.entries()].map(([step, lines]) => ({ step, said: lines.join("\n") }));
}

// The markers of one week, for the table beneath a chart.
export function markersIn(trend: CodeFindingTrend, step: number): CodeFindingMarker[] {
  return (trend.markers ?? []).filter((m) => stepOf(trend.points ?? [], m.at) === step);
}

// The parts a split is drawn with, in order: every tier and method, and each
// series the trend names, by name.
export function partsOf(trend: CodeFindingTrend, by: TrendSplit): string[] {
  const first = trend.points?.[0];
  if (!first) return [];
  if (by === "tier") return Object.keys(TIERS);
  if (by === "method") return Object.keys(first.by_method).sort();
  return Object.keys(first.by_series).sort();
}

// What a part of a split counts at one week.
export function partAt(point: Point, by: TrendSplit, part: string): number {
  const split = by === "tier" ? point.by_tier : by === "method" ? point.by_method : point.by_series;
  return split[part] ?? 0;
}
