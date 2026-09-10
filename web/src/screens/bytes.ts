// A size in bytes, between the form the server takes and the form a person
// reads.
//
// The server takes and returns a plain count of bytes, because that is what it
// compares an upload against. Nobody reads 26214400 as twenty-five megabytes,
// and a field that shows it is a field where a mistake is a factor of a
// thousand — the same failure the duration composer exists to prevent, in the
// other unit.

// The units offered, in bytes. Binary multiples, because that is what the
// shipped defaults are written as and what a storage bucket is measured in.
export const SIZES = [
  { unit: "bytes", bytes: 1 },
  { unit: "KB", bytes: 1024 },
  { unit: "MB", bytes: 1024 * 1024 },
  { unit: "GB", bytes: 1024 * 1024 * 1024 },
] as const;

export type Size = (typeof SIZES)[number]["unit"];

// Read a stored size as a whole number of the largest unit that divides it.
// Null where it is not a positive whole number of bytes, so a value somebody
// set deliberately is never rounded into a control that cannot express it.
export function readBytes(value: string): { count: number; unit: Size } | null {
  const text = value.trim();
  if (!/^\d+$/.test(text)) return null;
  const bytes = Number(text);
  if (!Number.isSafeInteger(bytes) || bytes <= 0) return null;
  for (const each of [...SIZES].reverse()) {
    if (bytes % each.bytes === 0) return { count: bytes / each.bytes, unit: each.unit };
  }
  return null;
}

// Write one back in the form the server takes.
export function writeBytes(count: number, unit: Size): string {
  const each = SIZES.find((one) => one.unit === unit) ?? SIZES[0];
  return String(Math.max(1, Math.round(count)) * each.bytes);
}

// A size as somebody would say it, for showing beside a value this cannot
// compose — one set from a script, or one that divides into nothing whole.
export function humaneBytes(value: string): string {
  const text = value.trim();
  if (!/^\d+$/.test(text)) return "";
  const bytes = Number(text);
  if (!Number.isSafeInteger(bytes) || bytes <= 0) return "";
  for (const each of [...SIZES].reverse()) {
    if (bytes >= each.bytes) {
      const scaled = bytes / each.bytes;
      const said = Number.isInteger(scaled) ? String(scaled) : scaled.toFixed(1);
      return `${said} ${each.unit}`;
    }
  }
  return `${bytes} bytes`;
}
