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
import { BANDS as LADDER, COLORS } from "./severities";

// The three shapes the reporting decisions name, drawn small. They sit inside
// panels rather than on a page of their own, so they carry no title and no
// legend — the panel says what they are, and a reading underneath says what
// they mean, which is the part a number cannot say for itself.

export type Point = {
  at?: string;
  open?: number;
  opened?: number;
  resolved?: number;
  by_severity?: Record<string, number>;
};

// The four bands, folded the way the server folds them.
//
// The server ranks, filters and clocks on four bands and reports the trend in
// the six words a feed uses. Something has to fold, and it was being done
// twice with two different answers: here, "unknown" was counted as low, and
// everywhere the server looks at it — the severity filter, the triage floor,
// the order, the deadline — it is a medium. So Home said 1,415 low where the
// list agreed on 38, and a thousand findings were one thing on one screen and
// another thing on the next.
//
// Folded here to match, because a rating with no word is treated as a medium
// rather than dismissed as a low, and the screen has no business disagreeing
// with what the deadline is set from.
export function folded(by: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const [word, count] of Object.entries(by)) {
    switch (word) {
      case "critical":
      case "high":
        out[word] = (out[word] ?? 0) + count;
        break;
      case "low":
      case "negligible":
      case "none":
        out.low = (out.low ?? 0) + count;
        break;
      default:
        out.medium = (out.medium ?? 0) + count;
    }
  }
  return out;
}

// Derived from the ladder rather than written beside it. Spelled out, a rung
// added to the ladder drew no band here and the split stopped summing to the
// count printed next to it — which is the one thing a split has to do.
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

// New, resolved and open together. Separately they are three numbers.
//
// Two bands rather than one axis. Open runs to thousands and a week's new or
// resolved to tens, so on a shared scale the two lines the chart exists for
// flatten into the baseline and vanish — which is what the first version did.
// Open is an area in the upper band with its endpoint named, because that is
// the number anybody reads; new against resolved sit beneath as paired bars on
// their own scale, so a week where new outran resolved shows as a taller bar,
// not as a second axis (the one thing a chart must never grow).
export function Pace({ points }: { points: Point[] }) {
  if (points.length === 0) return null;
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
  const news = points.map((p) => p.opened ?? 0);
  const dones = points.map((p) => p.resolved ?? 0);

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
  const most = Math.max(1, ...news, ...dones);
  const scale = (botH / 2 - 4) / most;
  const bw = Math.max(2, ((W - L - R) / n) * 0.34);

  const pts = opens.map((v, i) => `${x(i)},${y(v)}`).join(" ");
  const last = n - 1;

  return (
    <svg
      className="chart"
      viewBox={`0 0 ${W} ${T + topH + gap + botH + 18}`}
      role="img"
      aria-label={paceLabel(points)}
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
      <polyline className="open-line" points={pts} />
      <circle className="tip" cx={x(last)} cy={y(opens[last] ?? 0)} r={3.5} />
      <text
        className="axis"
        x={x(last) - 5}
        y={y(opens[last] ?? 0) - 8}
        textAnchor="end"
        style={{ fill: "var(--accent)", fontWeight: 600, fontSize: 11 }}
      >
        {(opens[last] ?? 0).toLocaleString()} open issues
      </text>

      <line className="zero" x1={L} x2={W - R} y1={zero} y2={zero} />
      {points.map((p, i) => {
        const cx = x(i);
        const up = (news[i] ?? 0) * scale;
        const down = (dones[i] ?? 0) * scale;
        return (
          <g key={p.at ?? i}>
            <rect className="bar-new" x={cx - bw - 1} y={zero - up} width={bw} height={up} rx={1}>
              <title>{`${day(p.at)}: ${news[i]} new`}</title>
            </rect>
            <rect className="bar-res" x={cx + 1} y={zero} width={bw} height={down} rx={1}>
              <title>{`${day(p.at)}: ${dones[i]} resolved`}</title>
            </rect>
          </g>
        );
      })}
      {points.map((p, i) =>
        i % 3 === 0 || i === last ? (
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

function paceLabel(points: Point[]): string {
  const first = points[0]?.open ?? 0;
  const last = points[points.length - 1]?.open ?? 0;
  const outran = points.filter((p) => (p.opened ?? 0) > (p.resolved ?? 0)).length;
  return `Open findings from ${first.toLocaleString()} to ${last.toLocaleString()} over ${points.length} steps, with new findings outrunning resolved in ${outran} of them`;
}

// The same total, split. A flat line with a rising critical share is getting
// worse, and one line cannot show that.
export function Mix({ points }: { points: Point[] }) {
  const data = points.map((p) => {
    const by = folded(p.by_severity ?? {});
    return {
      at: day(p.at),
      critical: by.critical ?? 0,
      high: by.high ?? 0,
      medium: by.medium ?? 0,
      low: by.low ?? 0,
    };
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

// What is open right now. A ring on its own says what somebody already knows,
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

// What is open at each build, side by side.
//
// Bars rather than a line: these are separate builds, not one thing measured
// over time, and a line between two releases draws a trend through a gap where
// nothing happened. Ordering is the server's, so the bars do not move between
// requests.
export function Across({ releases }: { releases: Release[] }) {
  const data = releases.map((r) => {
    const by = folded(r.by_severity ?? {});
    return {
      at: [r.stream, r.variant].filter(Boolean).join(" · "),
      critical: by.critical ?? 0,
      high: by.high ?? 0,
      medium: by.medium ?? 0,
      low: by.low ?? 0,
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

// What each release shipped with.
//
// Bars rather than a line, because a release is a frozen point and a line
// between two of them draws a path nothing travelled. The gap between two
// releases is months on a calendar and one step here, which is the whole
// reason this axis exists.
export function Releases({
  points,
}: {
  points: { stream?: string; open?: number; cut?: string }[];
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
      aria-label="Open issues in each release"
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
          <g key={`${point.stream}-${i}`}>
            <rect
              x={x}
              y={T + H - height}
              width={bar}
              height={Math.max(1, height)}
              fill="var(--accent)"
              rx={2}
            >
              <title>
                {point.stream}: {(point.open ?? 0).toLocaleString()} open
              </title>
            </rect>
            {/* Every release is named. A tick every other bar would leave
                somebody counting to work out which one they are looking at. */}
            <text className="axis" x={x + bar / 2} y={T + H + 16} textAnchor="middle">
              {point.stream}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
