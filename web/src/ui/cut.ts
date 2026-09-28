// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Text shortened to a number of characters, marked where it was cut.
//
// Counted in characters rather than in the units a string is stored in, so a
// cut never falls inside one character and leaves half of it on screen. The
// mark says the text goes on: a description stopping mid-sentence with nothing
// after it reads as the whole of it.
export function cut(text: string, most: number): string {
  const characters = Array.from(text);
  if (characters.length <= most) return text;
  return `${characters.slice(0, most).join("").trimEnd()}…`;
}
