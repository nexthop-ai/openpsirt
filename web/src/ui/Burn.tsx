// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Body } from "../api/client";
import { tickWords } from "./Charts";

// The two panels of a findings burndown: what is left with the day's flows
// beneath it and a dotted line to zero, and the running totals of added and
// done since day 0.

export type BurnPoint = Body<"BurnPointBody">;
export type Projection = Body<"ProjectionBody">;

const DAY = 86_400_000;

function md(at: string): string {
  return at.slice(5, 10);
}

function dayOf(at: string): number {
  return Date.parse(`${at.slice(0, 10)}T00:00:00Z`);
}

// Whether a day's date is written under the axis: every few days, and the
// last, with the one before the last left out within a step of it.
function labelled(i: number, last: number, every: number): boolean {
  return i === last || (i % every === 0 && last - i >= every);
}

// Round values from zero to a top, for a scale that starts at the floor: a
// burndown is read for how far it is from zero.
function ticksTo(hi: number, want: number): number[] {
  const raw = Math.max(1, hi) / want;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? mag * 10;
  const out: number[] = [];
  for (let v = 0; v <= hi; v += step) out.push(v);
  return out;
}

// The days a mark is drawn on: a first scan's baseline, and what came back
// after an upload lost most of a build. Neither is a move.
function burnMarks(points: BurnPoint[]): { step: number; said: string }[] {
  const out: { step: number; said: string }[] = [];
  points.forEach((p, i) => {
    const lines: string[] = [];
    if (p.first_scans > 0 || p.baseline > 0) {
      lines.push(`${md(p.at)}: first scan: ${p.baseline.toLocaleString()}`);
    }
    if (p.restored > 0) lines.push(`${md(p.at)}: returned after a gap: ${p.restored}`);
    if (lines.length > 0) out.push({ step: i, said: lines.join("\n") });
  });
  return out;
}

// Where the dotted line ends: at zero on the day it reaches it, or at the
// chart's right edge where that day is past it, at the count it would show
// there. Nothing where the backlog does not converge.
export function projectionEnd(
  points: BurnPoint[],
  ahead: Projection,
  horizon: number,
): { at: number; left: number } | null {
  const last = points[points.length - 1];
  if (!last || !ahead.converging || ahead.per_day <= 0 || last.left === 0) return null;
  const from = dayOf(last.at);
  const zero = ahead.zero_on ? dayOf(ahead.zero_on) : Infinity;
  if (zero <= horizon) return { at: zero, left: 0 };
  return { at: horizon, left: Math.max(0, last.left - ((horizon - from) / DAY) * ahead.per_day) };
}

// Left over time, from the start of day 0, with the day's flows beneath on
// their own scale: new and returned up, fixed and dismissed down. A dotted line
// runs from today to zero at the recent pace, and the chart widens to hold it,
// by as much again as is drawn at most.
export function Burn({
  points,
  start,
  since,
  ahead,
}: {
  points: BurnPoint[];
  start: number;
  since: string;
  ahead: Projection;
}) {
  if (points.length === 0) return null;
  const W = 560,
    L = 40,
    R = 10,
    T = 8;
  const topH = 110,
    gap = 16,
    botH = 50;
  const first = dayOf(since);
  const last = dayOf(points[points.length - 1]?.at ?? since);
  const drawn = Math.max(DAY, last - first);
  const end = projectionEnd(points, ahead, last + drawn);
  const right = end ? Math.max(last, end.at) : last;
  const x = (t: number) => L + ((t - first) / Math.max(DAY, right - first)) * (W - L - R);
  const xi = (i: number) => x(dayOf(points[i]?.at ?? since));

  const lefts = points.map((p) => p.left);
  const hi = Math.max(1, start, ...lefts) * 1.12;
  const y = (v: number) => T + topH - (v / hi) * topH;
  const ticks = ticksTo(hi, 3);
  const said = tickWords(ticks);

  const zero = T + topH + gap + botH / 2;
  const most = Math.max(
    1,
    ...points.map((p) => p.new + p.returned),
    ...points.map((p) => p.fixed + p.dismissed),
  );
  const scale = (botH / 2 - 4) / most;
  const bw = Math.max(2, ((xi(points.length - 1) - L) / Math.max(1, points.length)) * 0.5);

  // The line starts at day 0's end: its start is the same day on this axis,
  // and is said beneath the chart.
  const line = points.map((p, i) => `${xi(i)},${y(p.left)}`).join(" ");
  const n = points.length - 1;
  const tip = points[n]?.left ?? 0;
  const every = Math.max(1, Math.ceil(points.length / 8));
  const marks = burnMarks(points);

  return (
    <svg
      className="chart"
      viewBox={`0 0 ${W} ${T + topH + gap + botH + 18}`}
      role="img"
      aria-label={burnLabel(points, start, ahead)}
    >
      {ticks.map((v, i) => (
        <g key={v}>
          <line className="gridline" x1={L} x2={W - R} y1={y(v)} y2={y(v)} />
          <text className="axis" x={2} y={y(v) + 3}>
            {said[i]}
          </text>
        </g>
      ))}
      {marks.map((mark) => (
        <g key={mark.step} className="mark">
          <line x1={xi(mark.step)} x2={xi(mark.step)} y1={T} y2={T + topH} />
          <path d={`M${xi(mark.step) - 4},${T} h8 l-4,6 z`} />
          <title>{mark.said}</title>
        </g>
      ))}
      <polyline className="open-line" points={line} />
      {end && (
        <polyline className="projection" points={`${xi(n)},${y(tip)} ${x(end.at)},${y(end.left)}`}>
          <title>
            {ahead.zero_on ? `Zero by ${ahead.zero_on} at this pace` : "Toward zero at this pace"}
          </title>
        </polyline>
      )}
      <circle className="tip" cx={xi(n)} cy={y(tip)} r={3.5} />
      <text
        className="axis"
        x={xi(n) - 5}
        y={y(tip) - 8}
        textAnchor="end"
        style={{ fill: "var(--accent)", fontWeight: 600, fontSize: 11 }}
      >
        {tip.toLocaleString()} left
      </text>

      <line className="zero" x1={L} x2={W - R} y1={zero} y2={zero} />
      {points.map((p, i) => {
        const cx = xi(i);
        const up = p.new * scale;
        const back = p.returned * scale;
        const fixed = p.fixed * scale;
        const dismissed = p.dismissed * scale;
        return (
          <g key={p.at}>
            <rect className="bar-new" x={cx - bw / 2} y={zero - up} width={bw} height={up} rx={1}>
              <title>{`${md(p.at)}: ${p.new} new`}</title>
            </rect>
            <rect
              className="bar-ret"
              x={cx - bw / 2}
              y={zero - up - back}
              width={bw}
              height={back}
              rx={1}
            >
              <title>{`${md(p.at)}: ${p.returned} returned`}</title>
            </rect>
            <rect className="bar-res" x={cx - bw / 2} y={zero} width={bw} height={fixed} rx={1}>
              <title>{`${md(p.at)}: ${p.fixed} fixed`}</title>
            </rect>
            <rect
              className="bar-dis"
              x={cx - bw / 2}
              y={zero + fixed}
              width={bw}
              height={dismissed}
              rx={1}
            >
              <title>{`${md(p.at)}: ${p.dismissed} dismissed`}</title>
            </rect>
          </g>
        );
      })}
      {points.map((p, i) =>
        labelled(i, n, every) ? (
          <text key={p.at} className="axis" x={xi(i)} y={zero + botH / 2 + 12} textAnchor="middle">
            {md(p.at)}
          </text>
        ) : null,
      )}
      {end && ahead.zero_on && dayOf(ahead.zero_on) === end.at && (
        <text className="axis" x={x(end.at)} y={zero + botH / 2 + 12} textAnchor="end">
          {md(ahead.zero_on)}
        </text>
      )}
    </svg>
  );
}

// The key beneath a burndown.
export function BurnLegend() {
  return (
    <div className="legend">
      <span>
        <i style={{ background: "var(--accent)" }} /> Left
      </span>
      <span>
        <i className="dotted" /> At this pace
      </span>
      <span>
        <i style={{ background: "var(--sev-high)" }} /> New
      </span>
      <span>
        <i style={{ background: "var(--sev-critical)" }} /> Returned
      </span>
      <span>
        <i style={{ background: "var(--ok)" }} /> Fixed
      </span>
      <span>
        <i style={{ background: "var(--wait)" }} /> Dismissed
      </span>
      <span>
        <i className="dashed" /> First scan or gap
      </span>
    </div>
  );
}

// What the burndown shows, for a screen reader.
function burnLabel(points: BurnPoint[], start: number, ahead: Projection): string {
  const now = points[points.length - 1]?.left ?? 0;
  return `Left from ${start.toLocaleString()} to ${now.toLocaleString()} over ${points.length} days; ${paceWords(ahead, now)}`;
}

// The projection in words: the day it reaches zero, or that it does not.
export function paceWords(ahead: Projection, left = 1): string {
  if (left === 0) return "nothing is left";
  if (ahead.converging) {
    return ahead.zero_on
      ? `zero by ${ahead.zero_on} at this pace`
      : "more than ten years to zero at this pace";
  }
  const growing = -ahead.per_day;
  if (growing <= 0) return "not converging: added keeps pace with done";
  const about = growing >= 10 ? Math.round(growing) : Math.round(growing * 10) / 10;
  return `not converging: backlog growing about ${about.toLocaleString()} a day`;
}

// The running totals since day 0: added (new and returned) and done (fixed
// and dismissed), from zero on one axis. Done above added is a backlog
// shrinking.
type Running = { at: string; added: number; done: number };

export function running(points: BurnPoint[]): Running[] {
  let added = 0,
    done = 0;
  return points.map((p) => {
    added += p.new + p.returned;
    done += p.fixed + p.dismissed;
    return { at: p.at, added, done };
  });
}

export function AddedDone({ points, since }: { points: BurnPoint[]; since: string }) {
  const rows = running(points);
  if (rows.length === 0) return null;
  const W = 560,
    L = 40,
    R = 10,
    T = 8,
    H = 130;
  const first = dayOf(since);
  const last = dayOf(rows[rows.length - 1]?.at ?? since);
  const x = (at: string) => L + ((dayOf(at) - first) / Math.max(DAY, last - first)) * (W - L - R);
  const hi = Math.max(1, ...rows.map((r) => Math.max(r.added, r.done))) * 1.12;
  const y = (v: number) => T + H - (v / hi) * H;
  const ticks = ticksTo(hi, 3);
  const said = tickWords(ticks);
  const lineOf = (pick: (r: Running) => number) =>
    [`${L},${y(0)}`, ...rows.map((r) => `${x(r.at)},${y(pick(r))}`)].join(" ");
  const tip = rows[rows.length - 1] ?? { at: since, added: 0, done: 0 };
  const every = Math.max(1, Math.ceil(rows.length / 8));
  const doneHigher = tip.done >= tip.added;
  // The lower line's label sits under it, kept above the dates.
  const below = (v: number) => Math.min(y(v) + 12, T + H - 3);

  return (
    <svg
      className="chart"
      viewBox={`0 0 ${W} ${T + H + 18}`}
      role="img"
      aria-label={`Since ${since}: ${tip.added.toLocaleString()} added, ${tip.done.toLocaleString()} done`}
    >
      {ticks.map((v, i) => (
        <g key={v}>
          <line className="gridline" x1={L} x2={W - R} y1={y(v)} y2={y(v)} />
          <text className="axis" x={2} y={y(v) + 3}>
            {said[i]}
          </text>
        </g>
      ))}
      <polyline className="added-line" points={lineOf((r) => r.added)} />
      <polyline className="done-line" points={lineOf((r) => r.done)} />
      <text
        className="axis"
        x={x(tip.at) - 5}
        y={doneHigher ? below(tip.added) : y(tip.added) - 6}
        textAnchor="end"
        style={{ fill: "var(--sev-high)", fontWeight: 600, fontSize: 11 }}
      >
        {tip.added.toLocaleString()} added
      </text>
      <text
        className="axis"
        x={x(tip.at) - 5}
        y={doneHigher ? y(tip.done) - 6 : below(tip.done)}
        textAnchor="end"
        style={{ fill: "var(--ok)", fontWeight: 600, fontSize: 11 }}
      >
        {tip.done.toLocaleString()} done
      </text>
      {rows.map((r, i) =>
        labelled(i, rows.length - 1, every) ? (
          <text key={r.at} className="axis" x={x(r.at)} y={T + H + 14} textAnchor="middle">
            {md(r.at)}
          </text>
        ) : null,
      )}
    </svg>
  );
}
