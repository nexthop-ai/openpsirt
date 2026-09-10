// How a stored moment is written on screen.
//
// Two forms and no others. There were four in use at once, two of them
// machine-shaped: a date cut out of the stored string, the whole stored string
// interpolated with its time and offset, that string with the `T` replaced by a
// space, and nothing relative anywhere. A list somebody reads down and a list
// they read back stop agreeing the moment those differ, and the machine-shaped
// ones are the tool showing its storage rather than answering the question.
//
// Deliberately not localized. The stored form is UTC and the absolute form is
// the same everywhere, because these are dates people quote to each other
// across time zones — a deadline, an embargo, when a scan ran — and one that
// reads differently for two people looking at the same row is worse than one
// that reads unfamiliarly for both.

// on is the absolute form: the calendar day, as stored.
//
// Empty in, empty out. A moment that is not there is a different thing from one
// at the start of the epoch, and every caller of this has somewhere to say so
// in its own words.
export function on(moment: string | null | undefined): string {
  if (!moment) {
    return "";
  }
  return moment.slice(0, 10);
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
  const scale: [number, string][] = [
    [60, "minute"],
    [3600, "hour"],
    [86400, "day"],
    [604800, "week"],
    [2629800, "month"],
    [31557600, "year"],
  ];
  let size = 60;
  let unit = "minute";
  for (const [each, name] of scale) {
    if (seconds >= each) {
      size = each;
      unit = name;
    }
  }
  const n = Math.floor(seconds / size);
  return `${n} ${unit}${n === 1 ? "" : "s"} ago`;
}

function ahead(seconds: number): string {
  if (seconds < 60) {
    return "in a moment";
  }
  const scale: [number, string][] = [
    [60, "minute"],
    [3600, "hour"],
    [86400, "day"],
    [604800, "week"],
    [2629800, "month"],
    [31557600, "year"],
  ];
  let size = 60;
  let unit = "minute";
  for (const [each, name] of scale) {
    if (seconds >= each) {
      size = each;
      unit = name;
    }
  }
  const n = Math.floor(seconds / size);
  return `in ${n} ${unit}${n === 1 ? "" : "s"}`;
}
