// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The parts the two-band flow charts share: a line of what is open above, the
// flows that moved it as bars on either side of a zero line beneath, a mark
// on a step a first scan or a gap explains, and the dates under the axis. The
// issue trend's pace and the burndown are drawn from these.

// Whether a step's date is written under the axis: every few steps, and the
// last, with the one before the last left out within a step of it, where the
// two overprint.
export function labelled(i: number, last: number, every: number): boolean {
  return i === last || (i % every === 0 && last - i >= every);
}

// A handful of round values from a floor to a top, for a chart's grid.
export function roundTicks(lo: number, hi: number, want: number): number[] {
  const span = Math.max(1, hi - lo);
  const raw = span / want;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? mag * 10;
  const out: number[] = [];
  for (let v = Math.ceil(lo / step) * step; v <= hi; v += step) out.push(v);
  return out;
}

// What a mark says of one step: a first scan's baseline, and what came back
// after an upload lost most of a build. Neither is a move.
export function scanLines(
  date: string,
  p: { first_scans?: number; baseline?: number; restored?: number },
): string[] {
  const lines: string[] = [];
  if ((p.first_scans ?? 0) > 0 || (p.baseline ?? 0) > 0) {
    lines.push(`${date}: first scan: ${(p.baseline ?? 0).toLocaleString()}`);
  }
  if ((p.restored ?? 0) > 0) {
    lines.push(`${date}: returned after a gap: ${(p.restored ?? 0).toLocaleString()}`);
  }
  return lines;
}

// A mark on one step: a dashed rule through the upper band, said on hover.
export function FlowMark({
  x,
  top,
  height,
  said,
}: {
  x: number;
  top: number;
  height: number;
  said: string;
}) {
  return (
    <g className="mark">
      <line x1={x} x2={x} y1={top} y2={top + height} />
      <path d={`M${x - 4},${top} h8 l-4,6 z`} />
      <title>{said}</title>
    </g>
  );
}

// One flow of a step: its bar's class, its drawn height and what hover says.
type Flow = { className: string; height: number; said: string };

// One step's flows: what came in stacked up from the zero line, what went out
// stacked down from it, each in the order given.
export function FlowBars({
  cx,
  width,
  zero,
  up,
  down,
}: {
  cx: number;
  width: number;
  zero: number;
  up: Flow[];
  down: Flow[];
}) {
  const bar = (flow: Flow, y: number) => (
    <rect
      key={flow.className}
      className={flow.className}
      x={cx - width / 2}
      y={y}
      width={width}
      height={flow.height}
      rx={1}
    >
      <title>{flow.said}</title>
    </rect>
  );
  // Each bar starts where the ones before it on its side end.
  const before = (flows: Flow[], i: number) =>
    flows.slice(0, i).reduce((sum, flow) => sum + flow.height, 0);
  return (
    <g>
      {up.map((flow, i) => bar(flow, zero - before(up, i + 1)))}
      {down.map((flow, i) => bar(flow, zero + before(down, i)))}
    </g>
  );
}
