// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// What the two multi-value filter controls share: how a pick changes the
// selection, what the closed control says, and how the keys move through the
// open list.

// The selection after one word is turned on or off, kept in the order the
// words are offered rather than the order they were ticked, so the same
// selection makes the same address however it was reached — two links that
// ask the same thing are the same link.
export function toggled(
  offered: readonly (readonly [string, string])[],
  chosen: readonly string[],
  word: string,
  on: boolean,
): string[] {
  const next = new Set(chosen);
  if (on) next.add(word);
  else next.delete(word);
  return offered.map(([each]) => each).filter((each) => next.has(each));
}

// What a closed control says. One pick reads as itself; several read as the
// first and how many more, so the control is not one value with a strange
// name and still says which way it narrows.
export function summary(picked: readonly (readonly [string, string])[], anything: string): string {
  if (picked.length === 0) return anything;
  if (picked.length === 1) return picked[0]![1];
  return `${picked[0]![1]} +${picked.length - 1}`;
}

// Where a key moves the active item in an open list of `count`, wrapping at
// either end, or nothing for a key that does not move it.
export function moved(key: string, active: number, count: number): number | undefined {
  const last = count - 1;
  switch (key) {
    case "ArrowDown":
      return active >= last ? 0 : active + 1;
    case "ArrowUp":
      return active <= 0 ? last : active - 1;
    case "Home":
      return 0;
    case "End":
      return last;
  }
  return undefined;
}
