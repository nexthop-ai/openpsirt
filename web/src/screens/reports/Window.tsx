// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useSearchParams } from "react-router-dom";
import { DAY_MS } from "../../ui/when";

// The window a report sheet covers, and the words for it.
//
// One control and one naming rule, so a window is called the same thing on
// every sheet: a reader comparing two sheets cannot otherwise tell whether they
// asked the same question.
//
// The memberships stay per sheet, because which windows a question is worth
// asking over genuinely differs: a triage-latency figure over ten years says
// nothing, and an advisory count over a week says nothing either.

// The longest window any sheet offers. Ten years reads as "everything" and is
// also the bound on what the address may ask for: a date arithmetic that runs
// on a number from a query string is one edited address away from a throw.
const LONGEST = 3650;

// boundedAsked is a whole number the address asks for, checked rather than
// trusted.
//
// A window goes into date arithmetic on the render path, so `Number("x")` is
// not a wrong figure — it is `new Date(NaN).toISOString()`, which throws and
// takes the sheet down with it. It also goes to the server, which refuses a
// window it cannot answer for. So anything that is not a whole number from one
// to the most the sheet offers falls back to what the sheet asked for.
export function boundedAsked(
  params: URLSearchParams,
  name: string,
  most: number,
  fallback: number,
): number {
  const asked = params.get(name);
  if (asked === null) return fallback;
  const n = Number(asked);
  if (!Number.isFinite(n) || n < 1 || n > most) return fallback;
  return Math.floor(n);
}

// daysAsked is the window in days the address asks for.
export function daysAsked(params: URLSearchParams, fallback: number): number {
  return boundedAsked(params, "days", LONGEST, fallback);
}

// windowStart is when a window began, as the date the lists and the record
// take. Beside the reader of the number rather than in each sheet, so a figure
// and the list it opens ask the same question.
export function windowStart(days: number): string {
  return new Date(Date.now() - days * DAY_MS).toISOString().slice(0, 10);
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
//
// Both days are in it, the way a person reads "2026-01-01 to 2026-03-31". The
// server takes an end that is not itself in the period, so what is sent is
// the day after the last one picked.
export type Asked = { from: string; to: string };

// endExclusive is the day after a period's last day, which is the end the
// server and every list take. Nothing where the period has no end.
export function endExclusive(day: string): string {
  if (day === "") return "";
  const next = new Date(`${day}T00:00:00Z`);
  next.setUTCDate(next.getUTCDate() + 1);
  return next.toISOString().slice(0, 10);
}

// calendarDay is a day as the address names it, or nothing where it names no
// day on the calendar. A parser rolls a day past the end of its month into the
// next month rather than refusing it, and the day after that is what reaches
// the server.
export function calendarDay(value: string): string {
  if (!DAY.test(value)) return "";
  const named = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(named.getTime()) || named.toISOString().slice(0, 10) !== value) return "";
  return value;
}

// periodAsked is the period the address asks for, or neither date.
export function periodAsked(params: URLSearchParams): Asked {
  const kept = (name: string) => calendarDay(params.get(name) ?? "");
  const from = kept("from");
  const to = kept("to");
  // A period that ends before it starts holds nothing, and the server refuses
  // it. Dropped here so the sheet asks a question that can be answered rather
  // than drawing an error somebody has to read to understand. One that starts
  // and ends on the same day is that day.
  if (from !== "" && to !== "" && from > to) return { from: "", to: "" };
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
  // A sheet with no default window asks for none. Zero is not a window the
  // server can answer for — it carries a minimum of one — so it is left out
  // rather than sent and refused.
  if (!stated(period)) return days > 0 ? { days } : {};
  return {
    ...(period.from ? { from: period.from } : {}),
    ...(period.to ? { to: endExclusive(period.to) } : {}),
  };
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

// Segments offers a few whole numbers as one control and writes the one picked
// into the address, so a sheet somebody sends carries what they were looking
// at. Zero is the sheet's own default and leaves the parameter off. What
// `clears` names goes when a number is picked.
export function Segments({
  label,
  param,
  offered,
  chosen,
  words,
  clears = [],
}: {
  label: string;
  param: string;
  offered: readonly number[];
  chosen: number;
  words: (n: number) => string;
  clears?: readonly string[];
}) {
  const [params, setParams] = useSearchParams();
  return (
    <div className="seg" role="group" aria-label={label}>
      {offered.map((n) => (
        <button
          key={n}
          type="button"
          aria-pressed={chosen === n}
          onClick={() => {
            const next = new URLSearchParams(params);
            if (n === 0) next.delete(param);
            else next.set(param, String(n));
            for (const name of clears) next.delete(name);
            setParams(next);
          }}
        >
          {words(n)}
        </button>
      ))}
    </div>
  );
}

// WindowPicker is the window in days a sheet covers. The two ways of saying
// when cannot travel together, so naming a window drops the period as naming
// dates drops the window.
export function WindowPicker({ offered, days }: { offered: readonly number[]; days: number }) {
  return (
    <div className="controls">
      <Segments
        label="Window"
        param="days"
        offered={offered}
        chosen={days}
        words={wordsFor}
        clears={["from", "to"]}
      />
    </div>
  );
}
