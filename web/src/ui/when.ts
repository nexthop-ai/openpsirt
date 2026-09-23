// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The form a stored moment takes on screen.
//
// The absolute forms and the relative one, and nothing machine-shaped: never
// the stored string with its time and offset, and never that string with the
// `T` replaced by a space. Those are the tool showing its storage rather than
// answering the question.
//
// Deliberately not localized. The stored form is UTC and the absolute form is
// the same everywhere, because these are dates people quote to each other
// across time zones — a deadline, an embargo, when a scan ran — and one that
// reads differently for two people looking at the same row is worse than one
// that reads unfamiliarly for both.

// The shape a stored moment has: a calendar day, optionally followed by a time.
// Checked rather than assumed, because this takes whatever a caller hands it
// and sixteen files call it — a field that is not a moment at all would
// otherwise be drawn as its own first ten characters, which reads like a date
// and is not one.
const STORED = /^\d{4}-\d{2}-\d{2}(?:[T ]|$)/;

// on is the absolute form: the calendar day, as stored.
//
// Empty in, empty out. A moment that is not there is a different thing from one
// at the start of the epoch, and every caller of this has somewhere to say so
// in its own words — and so is a value that is not a moment, which is the same
// answer for the same reason.
export function on(moment: string | null | undefined): string {
  if (!moment || !STORED.test(moment)) {
    return "";
  }
  const day = moment.slice(0, 10);
  return Number.isNaN(new Date(day).getTime()) ? "" : day;
}

// at is the absolute form to the minute, in UTC and saying so.
//
// For a moment a window of hours counts from, where the day alone is not an
// answer: a window of a day that opened at 23:00 and one that opened at 01:00
// end on different days. UTC for the reason the day is: people quote these to
// each other across time zones.
export function at(moment: string | null | undefined): string {
  if (!moment || !STORED.test(moment)) {
    return "";
  }
  const then = new Date(moment);
  if (Number.isNaN(then.getTime())) {
    return "";
  }
  return `${then.toISOString().slice(0, 10)} ${then.toISOString().slice(11, 16)} UTC`;
}

// since is the relative form: how long ago, in the coarsest unit that still
// says something.
//
// For the reader who wants to know whether something is stale rather than
// exactly when it happened — "3 days ago" answers that and "2026-09-04" makes
// them work it out. Paired with the absolute form on the title, so the exact
// answer is one hover away and never lost.
export function since(moment: string | null | undefined, now: Date = new Date()): string {
  if (!moment) {
    return "";
  }
  const then = new Date(moment);
  if (Number.isNaN(then.getTime())) {
    return "";
  }
  const seconds = Math.round((now.getTime() - then.getTime()) / 1000);
  if (seconds < 0) {
    // Ahead of now: a deadline, a disclosure date, an end of life. The same
    // scale read the other way, because "in 3 days" and "3 days ago" are the
    // same question about different sides of now.
    return ahead(-seconds);
  }
  if (seconds < 60) {
    return "just now";
  }
  return `${magnitude(seconds)} ago`;
}

// lasted is how long something took, between two stored moments.
//
// A run says when it started and when it finished and the screen drew only the
// second, so "did the nightly scan take four minutes or four hours" — the
// question somebody asks when a build is late — had no answer on the page
// about that run. Seconds are said outright below a minute, because a scan
// that took nine seconds and one that took fifty are different things and
// "0 minutes" says neither.
export function lasted(from: string | null | undefined, to: string | null | undefined): string {
  if (!from || !to) {
    return "";
  }
  const began = new Date(from).getTime();
  const ended = new Date(to).getTime();
  if (Number.isNaN(began) || Number.isNaN(ended) || ended < began) {
    return "";
  }
  const seconds = Math.round((ended - began) / 1000);
  if (seconds < 60) {
    return `${seconds} second${seconds === 1 ? "" : "s"}`;
  }
  return magnitude(seconds);
}

function ahead(seconds: number): string {
  if (seconds < 60) {
    return "in a moment";
  }
  return `in ${magnitude(seconds)}`;
}

// The units an interval is said in, largest that fits winning.
//
// One table. It was written twice, once per side of now, and a unit added to
// one copy and not the other makes "3 days ago" and "in 3 days" answer
// differently about the same interval — the failure the severity ladder has a
// gate against, one table down.
const SCALE: [number, string][] = [
  [60, "minute"],
  [3600, "hour"],
  [86400, "day"],
  [604800, "week"],
  [2629800, "month"],
  [31557600, "year"],
];

// magnitude is how long an interval is, in words, with no sense of direction.
// The side of now it falls on is the caller's sentence to write.
function magnitude(seconds: number): string {
  let size = 60;
  let unit = "minute";
  for (const [each, name] of SCALE) {
    if (seconds >= each) {
      size = each;
      unit = name;
    }
  }
  const n = Math.floor(seconds / size);
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}
