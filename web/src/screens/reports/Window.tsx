import { useSearchParams } from "react-router-dom";

// How long a report sheet covers, and the words for it.
//
// One control and one naming rule. Three sheets each had their own copy of
// the segmented control and its own rule for what to call a number, so a
// 365-day window was "a year" on one sheet and "365 days" on another — a
// reader comparing the two cannot tell whether they asked the same question.
// That is the failure the severity ladder has a gate against, one table down.
//
// The memberships stay per sheet, because which windows a question is worth
// asking over genuinely differs: a triage-latency figure over ten years says
// nothing, and an advisory count over a week says nothing either.

// The longest window any sheet offers. Ten years reads as "everything" and is
// also the bound on what the address may ask for: a date arithmetic that runs
// on a number from a query string is one edited address away from a throw.
const LONGEST = 3650;

// daysAsked is the window the address asks for, checked rather than trusted.
//
// The value goes into date arithmetic on the render path, so `Number("x")` is
// not a wrong figure — it is `new Date(NaN).toISOString()`, which throws and
// takes the sheet down with it. It also goes to the server, which refuses a
// window it cannot answer for. So anything that is not a whole number of days
// inside the range any sheet offers falls back to what the sheet asked for.
export function daysAsked(params: URLSearchParams, fallback: number): number {
  const asked = params.get("days");
  if (asked === null) return fallback;
  const days = Number(asked);
  if (!Number.isFinite(days) || days < 1 || days > LONGEST) return fallback;
  return Math.floor(days);
}

// windowStart is when a window began, as the date the lists and the record
// take. Beside the reader of the number rather than in each sheet: two sheets
// held a copy, and a link built from one of them is what makes a figure and
// the list it opens ask the same question.
export function windowStart(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
}

// wordsFor is what one window is called, wherever it is named.
export function wordsFor(days: number): string {
  if (days >= LONGEST) return "everything";
  if (days === 365) return "a year";
  return `${days} days`;
}

// coveringWords is the same window as the phrase a sheet's heading takes.
export function coveringWords(days: number): string {
  if (days >= LONGEST) return "everything";
  if (days === 365) return "the last year";
  return `the last ${days} days`;
}

// A period is two dates rather than a rolling window, because a window ending
// today cannot say "last financial year" — which is the question an auditor
// asks and the one a quarterly review is written from.

// The shape a date has in the address. Checked rather than trusted, for the
// reason the window is: it reaches date arithmetic on the render path and the
// server, and an edited address is the ordinary way a wrong one arrives.
const DAY = /^\d{4}-\d{2}-\d{2}$/;

// Asked is a period somebody asked for. Either side may be missing: a start
// with no end runs to now, and an end with no start runs from the beginning.
export type Asked = { from: string; to: string };

// periodAsked is the period the address asks for, or neither date.
export function periodAsked(params: URLSearchParams): Asked {
  const kept = (name: string) => {
    const value = params.get(name) ?? "";
    if (!DAY.test(value) || Number.isNaN(new Date(value).getTime())) return "";
    return value;
  };
  const from = kept("from");
  const to = kept("to");
  // A period that ends before it starts holds nothing, and the server refuses
  // it. Dropped here so the sheet asks a question that can be answered rather
  // than drawing an error somebody has to read to understand.
  if (from !== "" && to !== "" && from >= to) return { from: "", to: "" };
  return { from, to };
}

// stated says whether a period was asked for at all.
export function stated(period: Asked): boolean {
  return period.from !== "" || period.to !== "";
}

// asked is what a report is sent: the period where there is one, and the
// rolling window otherwise. The two are ways of saying the same thing and the
// server refuses both together.
export function asked(period: Asked, days: number): { from?: string; to?: string; days?: number } {
  if (!stated(period)) return { days };
  return { ...(period.from ? { from: period.from } : {}), ...(period.to ? { to: period.to } : {}) };
}

// coveringPeriod is what a sheet's heading calls the stretch it covers.
export function coveringPeriod(period: Asked, days: number): string {
  if (!stated(period)) return coveringWords(days);
  if (period.from === "") return `everything up to ${period.to}`;
  if (period.to === "") return `${period.from} onwards`;
  return `${period.from} to ${period.to}`;
}

// PeriodPicker writes two dates into the address beside the window picker, so
// a sheet somebody sends carries the stretch they were reading.
export function PeriodPicker({ period }: { period: Asked }) {
  const [params, setParams] = useSearchParams();
  const set = (name: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value === "") next.delete(name);
    else next.set(name, value);
    // The two ways of saying when cannot travel together, so naming dates
    // drops the window rather than sending a request the server refuses.
    if (value !== "") next.delete("days");
    setParams(next);
  };
  return (
    <div className="controls">
      <label>
        From <input type="date" value={period.from} onChange={(e) => set("from", e.target.value)} />
      </label>
      <label>
        To <input type="date" value={period.to} onChange={(e) => set("to", e.target.value)} />
      </label>
      {stated(period) && (
        <button
          type="button"
          onClick={() => {
            const next = new URLSearchParams(params);
            next.delete("from");
            next.delete("to");
            setParams(next);
          }}
        >
          Clear
        </button>
      )}
    </div>
  );
}

// WindowPicker is the picker itself. It writes the choice into the address, so a
// sheet somebody sends carries the window they were looking at.
export function WindowPicker({ offered, days }: { offered: readonly number[]; days: number }) {
  const [params, setParams] = useSearchParams();
  return (
    <div className="controls">
      <div className="seg" role="group" aria-label="Window">
        {offered.map((n) => (
          <button
            key={n}
            type="button"
            aria-pressed={days === n}
            onClick={() => {
              const next = new URLSearchParams(params);
              next.set("days", String(n));
              setParams(next);
            }}
          >
            {wordsFor(n)}
          </button>
        ))}
      </div>
    </div>
  );
}
