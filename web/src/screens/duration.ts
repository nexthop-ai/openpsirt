// A length of time, between the form the server takes and the form a person
// types.
//
// The server takes and returns Go's duration syntax — "8760h", "12h0m0s" —
// because that is what its own clock parses and what the API returns
// everywhere. Nobody types "8760h" meaning a year, and a field that demands it
// is a field where a mistake is a factor of twenty-four.
//
// So the value is composed rather than typed: a number and a unit. The stored
// form is still shown, because it is what the API answers with and what an
// operator setting this from a script has to write.

// The units offered, in hours. Weeks and days are how deadlines are actually
// said; hours is what a short one is. Anything finer is a number of hours,
// which is why the composer gives up rather than growing a minutes field —
// see `read` below.
export const UNITS = [
  { unit: "hours", hours: 1 },
  { unit: "days", hours: 24 },
  { unit: "weeks", hours: 24 * 7 },
] as const;

export type Unit = (typeof UNITS)[number]["unit"];

// Read a stored duration as a whole number of the largest unit that divides
// it. Null where it is not a whole number of hours — a value like "90m" is
// real, was set by somebody who meant it, and must not be quietly rounded into
// a control that can only say hours.
export function read(value: string): { count: number; unit: Unit } | null {
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(value.trim());
  if (!m || !value.trim()) return null;
  const hours = Number(m[1] ?? 0) + Number(m[2] ?? 0) / 60 + Number(m[3] ?? 0) / 3600;
  if (hours <= 0 || !Number.isInteger(hours)) return null;
  for (const each of [...UNITS].reverse()) {
    if (hours % each.hours === 0) return { count: hours / each.hours, unit: each.unit };
  }
  return null;
}

// Write one back in the form the server takes.
export function write(count: number, unit: Unit): string {
  const each = UNITS.find((one) => one.unit === unit) ?? UNITS[0];
  return `${Math.max(1, Math.round(count)) * each.hours}h`;
}

// A length of time as somebody would say it, for showing beside a value that
// was not composed here — a duration set from a script, or one this cannot
// compose at all.
export function humane(value: string): string {
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(value.trim());
  if (!m || !value.trim()) return "";
  const hours = Number(m[1] ?? 0) + Number(m[2] ?? 0) / 60 + Number(m[3] ?? 0) / 3600;
  if (hours === 0) return "";
  if (hours % 24 === 0) {
    const days = hours / 24;
    if (days % 365 === 0) return days === 365 ? "1 year" : `${days / 365} years`;
    return days === 1 ? "1 day" : `${days} days`;
  }
  if (hours >= 1 && Number.isInteger(hours)) return hours === 1 ? "1 hour" : `${hours} hours`;
  return "";
}

// A stored value the composer takes. A duration it can read, or
// nothing at all: a setting nobody has set has no unit to show, and a plain
// text box is the one control that cannot ask for one.
export function composable(value: string): boolean {
  return value.trim() === "" || read(value) !== null;
}
