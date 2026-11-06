// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Body } from "../api/client";
import { BANDS as LADDER, BELOW_LOW, COLORS } from "./severities";
import { type Step, began, outran, settled } from "./trend";

// The step a calendar trend is drawn in, the windows each is asked over, and
// the words a heading carries. Daily shows a team fixing dozens a day; weekly
// smooths a quarter.
export type TrendStep = "day" | "week";
const TREND_DAYS = 30;
const TREND_WEEKS = 12;

// The window a step asks the server for.
export function stepQuery(step: TrendStep): { days: number } | { weeks: number } {
  return step === "day" ? { days: TREND_DAYS } : { weeks: TREND_WEEKS };
}

// The window as a heading names it.
export function stepSaid(step: TrendStep): string {
  return step === "day" ? `${TREND_DAYS} days` : `${TREND_WEEKS} weeks`;
}

// The step's plural, as a reading counts steps.
export function stepUnit(step: TrendStep): string {
  return step === "day" ? "days" : "weeks";
}

// The switch between daily and weekly steps on a trend panel.
export function StepSwitch({
  step,
  onStep,
}: {
  step: TrendStep;
  onStep: (step: TrendStep) => void;
}) {
  return (
    <div className="seg" role="group" aria-label="Step">
      {(["day", "week"] as const).map((each) => (
        <button key={each} type="button" aria-pressed={step === each} onClick={() => onStep(each)}>
          {each === "day" ? "Daily" : "Weekly"}
        </button>
      ))}
    </div>
  );
}

// The three shapes the reporting decisions name, drawn small. They sit inside
// panels rather than on a page of their own, so they carry no title and no
// legend — the panel says what they are, and a reading underneath says what
// they mean, which is the part a number cannot say for itself.

type Point = Step & { at?: string };

// The four bands, folded the way the server folds them.
//
// The server ranks, filters and clocks on four bands and reports the trend in
// the six words a feed uses. Folded here the way the server folds, because a
// rating with no word is treated as a medium rather than dismissed as a low,
// and the screen has no business disagreeing with what the deadline is set
// from: counted as low, one real deployment read 1,415 low on the front page
// where the list agreed on 38.
//
// Seeded from the ladder, so every band the chart draws a series for is a key
// of every row, and a split always sums to its count. The words are the
// ladder's own: a band stays, the words beneath low are low, and every other
// word is medium.
export function folded(by: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = Object.fromEntries(LADDER.map((band) => [band, 0]));
  for (const [word, count] of Object.entries(by)) {
    const band = rungs.has(word) ? word : beneath.has(word) ? "low" : "medium";
    out[band] = (out[band] ?? 0) + count;
  }
  return out;
}

const rungs = new Set<string>(LADDER);
const beneath = new Set<string>(BELOW_LOW);

// Derived from the ladder rather than written beside it, so a rung added to the
// ladder is a band here and the split still sums to the count beside it.
const BANDS = LADDER.map((key) => ({ key, color: COLORS[key] }));

const tip = {
  background: "var(--surface)",
  border: "1px solid var(--line)",
  borderRadius: 6,
  fontSize: 12,
  color: "var(--ink)",
};

const axis = { fontSize: 11, fill: "var(--faint)" };

// Counts here run to five figures, and a narrow axis clips them to their last
// two digits — which reads as data rather than as a layout fault. Shortened so
// the width is predictable whatever the numbers do.
function brief(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(value >= 10_000 ? 0 : 1)}k`;
  return String(value);
}

function day(at?: string): string {
  return (at ?? "").slice(5, 10);
}

// Open, with new, returned and corrected beneath it. Separately they are
// numbers; together they say whether a team is keeping pace.
//
// Two bands rather than one axis. Open runs to thousands and a step's flows to
// tens, so on a shared scale the flows flatten into the baseline. Open is an
// area in the upper band with its endpoint named; new and returned stack above
// a zero line and corrected hangs below it, on their own scale. A first scan is
// no bar: it is a dashed mark saying what it brought, so the inventory
// arriving neither sets the bars' scale nor reads as work.
//
// Drawn from the first step that holds anything, so the open line's scale
// starts where scanning started.

// The words a pace chart is drawn with: its line's name at the endpoint, what
// the whole chart shows for a screen reader, and what the bars count.
type PaceWords = { line: string; what: string; fresh: string; back: string; done: string };
const ISSUE_WORDS: PaceWords = {
  line: "open issues",
  what: "Open issues",
  fresh: "new",
  back: "returned",
  done: "corrected",
};

// A mark on a step of a pace chart: what changed in it, said on hover. A
// step carrying one is drawn with a dashed rule through the upper band, so a
// jump a first scan or an analyzer upgrade made does not read as new work or
// a clean-up.
export type PaceMark = { step: number; said: string };

// The marks a chart draws over the steps it draws: those given, moved to the
// steps that remain once the leading empty ones are dropped, and one at each
// first scan saying what it brought. Two on one step are one mark.
export function paceMarks(points: Point[], marks: PaceMark[], from: number): PaceMark[] {
  const said = new Map<number, string[]>();
  const add = (step: number, line: string) => said.set(step, [...(said.get(step) ?? []), line]);
  for (const mark of marks) if (mark.step >= from) add(mark.step - from, mark.said);
  points.slice(from).forEach((p, i) => {
    if ((p.first_scans ?? 0) > 0 || (p.baseline ?? 0) > 0) {
      add(i, `${day(p.at)}: first scan: ${(p.baseline ?? 0).toLocaleString()}`);
    }
  });
  return [...said.entries()]
    .sort(([a], [b]) => a - b)
    .map(([step, lines]) => ({ step, said: lines.join("\n") }));
}

export function Pace({
  points: all,
  words = ISSUE_WORDS,
  marks: given = [],
  unit = "steps",
}: {
  points: Point[];
  words?: PaceWords;
  marks?: PaceMark[];
  unit?: string;
}) {
  const from = began(all);
  const points = all.slice(from);
  if (points.length === 0) return null;
  const marks = paceMarks(all, given, from);
  const W = 560,
    L = 40,
    R = 10,
    T = 8;
  const topH = 96,
    gap = 16,
    botH = 46;
  const n = points.length;
  const x = (i: number) => (n === 1 ? (L + W - R) / 2 : L + (i * (W - L - R)) / (n - 1));
  const opens = points.map((p) => p.open ?? 0);
  const news = points.map((p) => p.new ?? 0);
  const backs = points.map((p) => p.returned ?? 0);
  const dones = points.map((p) => p.corrected ?? 0);

  // The upper band's scale is fitted to what open actually spans, so a flat
  // backlog reads as flat rather than as a line pinned to the floor.
  const hiOpen = Math.max(1, ...opens);
  const loOpen = Math.min(...opens);
  const pad = Math.max(1, (hiOpen - loOpen) * 0.15);
  const lo = Math.max(0, loOpen - pad),
    hi = hiOpen + pad;
  const y = (v: number) => T + topH - ((v - lo) / (hi - lo)) * topH;
  const ticks = niceTicks(lo, hi, 3);

  const zero = T + topH + gap + botH / 2;
  const most = Math.max(1, ...news.map((v, i) => v + (backs[i] ?? 0)), ...dones);
  const scale = (botH / 2 - 4) / most;
  const bw = Math.max(2, ((W - L - R) / n) * 0.34);

  const pts = opens.map((v, i) => `${x(i)},${y(v)}`).join(" ");
  const last = n - 1;
  const every = Math.max(1, Math.ceil(n / 8));

  return (
    <svg
      className="chart"
      viewBox={`0 0 ${W} ${T + topH + gap + botH + 18}`}
      role="img"
      aria-label={paceLabel(points, words, unit)}
    >
      {ticks.map((v) => (
        <g key={v}>
          <line className="gridline" x1={L} x2={W - R} y1={y(v)} y2={y(v)} />
          <text className="axis" x={2} y={y(v) + 3}>
            {brief(v)}
          </text>
        </g>
      ))}
      <polygon className="open-area" points={`${L},${T + topH} ${pts} ${W - R},${T + topH}`} />
      {marks.map((mark) => (
        <g key={mark.step} className="mark">
          <line x1={x(mark.step)} x2={x(mark.step)} y1={T} y2={T + topH} />
          <path d={`M${x(mark.step) - 4},${T} h8 l-4,6 z`} />
          <title>{mark.said}</title>
        </g>
      ))}
      <polyline className="open-line" points={pts} />
      <circle className="tip" cx={x(last)} cy={y(opens[last] ?? 0)} r={3.5} />
      <text
        className="axis"
        x={x(last) - 5}
        y={y(opens[last] ?? 0) - 8}
        textAnchor="end"
        style={{ fill: "var(--accent)", fontWeight: 600, fontSize: 11 }}
      >
        {(opens[last] ?? 0).toLocaleString()} {words.line}
      </text>

      <line className="zero" x1={L} x2={W - R} y1={zero} y2={zero} />
      {points.map((p, i) => {
        const cx = x(i);
        const up = (news[i] ?? 0) * scale;
        const back = (backs[i] ?? 0) * scale;
        const down = (dones[i] ?? 0) * scale;
        return (
          <g key={p.at ?? i}>
            <rect className="bar-new" x={cx - bw / 2} y={zero - up} width={bw} height={up} rx={1}>
              <title>{`${day(p.at)}: ${news[i]} ${words.fresh}`}</title>
            </rect>
            <rect
              className="bar-ret"
              x={cx - bw / 2}
              y={zero - up - back}
              width={bw}
              height={back}
              rx={1}
            >
              <title>{`${day(p.at)}: ${backs[i]} ${words.back}`}</title>
            </rect>
            <rect className="bar-res" x={cx - bw / 2} y={zero} width={bw} height={down} rx={1}>
              <title>{`${day(p.at)}: ${dones[i]} ${words.done}`}</title>
            </rect>
          </g>
        );
      })}
      {points.map((p, i) =>
        i % every === 0 || i === last ? (
          <text
            key={p.at ?? i}
            className="axis"
            x={x(i)}
            y={zero + botH / 2 + 12}
            textAnchor="middle"
          >
            {day(p.at)}
          </text>
        ) : null,
      )}
    </svg>
  );
}

// The key beneath an issue trend: the line, the three bars and the mark.
export function PaceLegend() {
  return (
    <div className="legend">
      <span>
        <i style={{ background: "var(--accent)" }} /> Open issues
      </span>
      <span>
        <i style={{ background: "var(--sev-high)" }} /> New
      </span>
      <span>
        <i style={{ background: "var(--sev-critical)" }} /> Returned
      </span>
      <span>
        <i style={{ background: "var(--ok)" }} /> Corrected
      </span>
      <span>
        <i className="dashed" /> First scan
      </span>
    </div>
  );
}

// A handful of round values inside a range, for the upper band's grid.
function niceTicks(lo: number, hi: number, want: number): number[] {
  const span = Math.max(1, hi - lo);
  const raw = span / want;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? mag * 10;
  const out: number[] = [];
  for (let v = Math.ceil(lo / step) * step; v <= hi; v += step) out.push(v);
  return out;
}

// What the chart shows, for a screen reader: open from where scanning began,
// how often arrivals outran corrections, and what first scans brought.
export function paceLabel(points: Point[], words: PaceWords, unit: string): string {
  const first = points[0]?.open ?? 0;
  const last = points[points.length - 1]?.open ?? 0;
  const ahead = points.filter(outran).length;
  const baseline = points.reduce((sum, p) => sum + (p.baseline ?? 0), 0);
  const scans = baseline > 0 ? `; first scans brought ${baseline.toLocaleString()}` : "";
  return `${words.what} from ${first.toLocaleString()} to ${last.toLocaleString()} over ${points.length} ${unit}, with ${words.fresh} and ${words.back} outrunning ${words.done} in ${ahead} of them${scans}`;
}

// The same total, split. A flat line with a rising critical share is getting
// worse, and one line cannot show that.
export function Mix({ points }: { points: Point[] }) {
  const data = settled(points).map((p) => {
    return { at: day(p.at), ...folded(p.by_severity ?? {}) };
  });
  if (data.length === 0) return null;
  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid strokeOpacity={0.14} vertical={false} />
        <XAxis dataKey="at" tick={axis} tickLine={false} axisLine={false} />
        <YAxis tick={axis} tickLine={false} axisLine={false} width={46} tickFormatter={brief} />
        <Tooltip contentStyle={tip} />
        {BANDS.map((band) => (
          <Area
            key={band.key}
            type="monotone"
            dataKey={band.key}
            stackId="1"
            stroke={band.color}
            fill={band.color}
            fillOpacity={0.5}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

// One part of a stacked chart: the key each row counts it under, the words
// its tooltip names it by, and the token it is drawn in.
export type StackPart = { key: string; label: string; color: string };

// A total split into parts over time, stacked so the top edge is the total
// and each band a part's share of it.
export function Stack({
  rows,
  parts,
}: {
  rows: ({ at?: string } & Record<string, number | string | undefined>)[];
  parts: StackPart[];
}) {
  if (rows.length === 0 || parts.length === 0) return null;
  const data = rows.map((row) => ({ ...row, at: day(row.at as string | undefined) }));
  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid strokeOpacity={0.14} vertical={false} />
        <XAxis dataKey="at" tick={axis} tickLine={false} axisLine={false} />
        <YAxis tick={axis} tickLine={false} axisLine={false} width={46} tickFormatter={brief} />
        <Tooltip contentStyle={tip} />
        {parts.map((part) => (
          <Area
            key={part.key}
            type="monotone"
            dataKey={part.key}
            name={part.label}
            stackId="1"
            stroke={part.color}
            fill={part.color}
            fillOpacity={0.5}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

// The open count right now. A ring on its own says what somebody already knows,
// so the numbers are beside it rather than inside it.
export function Ring({ point }: { point?: Point }) {
  const by = folded(point?.by_severity ?? {});
  const slices = BANDS.map((band) => ({
    name: band.key,
    color: band.color,
    value: by[band.key] ?? 0,
  })).filter((slice) => slice.value > 0);

  if (slices.length === 0) {
    return <p className="reading">Nothing is open.</p>;
  }

  return (
    <div className="sevring">
      <PieChart width={132} height={132}>
        <Pie
          data={slices}
          dataKey="value"
          cx="50%"
          cy="50%"
          innerRadius={40}
          outerRadius={62}
          paddingAngle={1}
          stroke="none"
        >
          {slices.map((slice) => (
            <Cell key={slice.name} fill={slice.color} />
          ))}
        </Pie>
        <Tooltip contentStyle={tip} />
      </PieChart>
      <ul className="ringkey">
        {slices.map((slice) => (
          <li key={slice.name}>
            <i style={{ background: slice.color }} />
            {slice.name}
            <span className="n">{slice.value.toLocaleString()}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// The server's own shape. Restating it here is the bug this codebase has
// already been bitten by once — a hand-copied row type compiles perfectly
// while quietly missing whatever the server grew since it was written — and
// it was re-introduced in the same change that declared the class fixed.
export type Release = Body<"ReleaseBody">;

// The open count at each build, side by side.
//
// Bars rather than a line: these are separate builds, not one thing measured
// over time, and a line between two releases draws a trend through a gap where
// nothing happened. Ordering is the server's, so the bars do not move between
// requests.
export function Across({ releases }: { releases: Release[] }) {
  const data = releases.map((r) => {
    return {
      at: [r.branch_or_tag, r.variant].filter(Boolean).join(" · "),
      ...folded(r.by_severity ?? {}),
    };
  });
  if (data.length === 0) return null;
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid strokeOpacity={0.14} vertical={false} />
        <XAxis dataKey="at" tick={axis} tickLine={false} axisLine={false} interval={0} />
        <YAxis tick={axis} tickLine={false} axisLine={false} width={46} tickFormatter={brief} />
        <Tooltip contentStyle={tip} />
        {BANDS.map((band) => (
          <Bar key={band.key} dataKey={band.key} stackId="1" fill={band.color} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

// The counts each release shipped with.
//
// Bars rather than a line, because a release is a frozen point and a line
// between two of them draws a path nothing travelled. The gap between two
// releases is months on a calendar and one step here, which is the whole
// reason this axis exists.
export function Releases({
  points,
  counts = "open issues",
  each = "open",
}: {
  points: { branch_or_tag?: string; branch_or_tag_name?: string; open?: number; cut?: string }[];
  // What the bars count, for the chart's label and each bar's tooltip.
  counts?: string;
  each?: string;
}) {
  if (points.length === 0) return null;
  const W = 560,
    L = 40,
    R = 10,
    T = 8,
    H = 120;
  const most = Math.max(1, ...points.map((p) => p.open ?? 0));
  const slot = (W - L - R) / points.length;
  const bar = Math.min(48, slot * 0.62);

  return (
    <svg
      viewBox={`0 0 ${W} ${H + 34}`}
      className="chart"
      role="img"
      aria-label={`${counts.charAt(0).toUpperCase()}${counts.slice(1)} in each release`}
    >
      {[0, 0.5, 1].map((f) => (
        <line
          key={f}
          className="gridline"
          x1={L}
          x2={W - R}
          y1={T + H - f * H}
          y2={T + H - f * H}
        />
      ))}
      {[0, most].map((v, i) => (
        <text key={v} className="axis" x={L - 6} y={T + H - i * H + 4} textAnchor="end">
          {v.toLocaleString()}
        </text>
      ))}
      {points.map((point, i) => {
        const height = ((point.open ?? 0) / most) * H;
        const x = L + i * slot + (slot - bar) / 2;
        return (
          <g key={`${point.branch_or_tag}-${i}`}>
            <rect
              x={x}
              y={T + H - height}
              width={bar}
              height={Math.max(1, height)}
              fill="var(--accent)"
              rx={2}
            >
              <title>
                {point.branch_or_tag_name || point.branch_or_tag}:{" "}
                {(point.open ?? 0).toLocaleString()} {each}
              </title>
            </rect>
            {/* Every release is named. A tick every other bar would leave
                somebody counting to work out which one they are looking at. */}
            <text className="axis" x={x + bar / 2} y={T + H + 16} textAnchor="middle">
              {point.branch_or_tag_name || point.branch_or_tag}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
