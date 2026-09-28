// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Text shortened to a number of characters, marked where it was cut.
//
// Counted in what a reader sees as one character, so a cut never falls inside
// a flag, an emoji with a skin tone or a letter with a combining accent and
// leaves half of it on screen. The mark says the text goes on: a description
// stopping mid-sentence with nothing after it reads as the whole of it.
const GRAPHEMES = new Intl.Segmenter(undefined, { granularity: "grapheme" });

export function cut(text: string, most: number): string {
  const characters = Array.from(GRAPHEMES.segment(text), (each) => each.segment);
  if (characters.length <= most) return text;
  return `${characters.slice(0, most).join("").trimEnd()}…`;
}
