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
