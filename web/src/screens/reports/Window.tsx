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

// wordsFor is what one window is called, wherever it is named.
export function wordsFor(days: number): string {
  if (days >= 3650) return "everything";
  if (days === 365) return "a year";
  return `${days} days`;
}

// coveringWords is the same window as the phrase a sheet's heading takes.
export function coveringWords(days: number): string {
  if (days >= 3650) return "everything";
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
