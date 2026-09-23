// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A group's decision state, as the one word a row shows.
//
// Written twice, and the two copies already disagreed. The findings list
// and the issue screen show the same rows, and a group with some places
// answered and the rest never decided read "Partly" on one and "Undecided" on
// the other — the same fact, two words, because each screen had spelled the
// mapping out for itself under a comment saying they must not come to mean
// different things by "decided".
//
// The five words the state filter takes, plus the two states a filter has no
// name for: a claim sent back to its author, which is what the proposer is
// looking for in a list, and the empty state — some places answered and the
// rest not, which is neither decided nor undecided and has to say so.
export type Decided = { word: string; cls: string };

export function decidedAs(state?: string, sentBack?: boolean): Decided {
  if (sentBack) return { word: "Rejected", cls: "lapsed" };
  switch (state) {
    case "agreed":
      return { word: "Decided", cls: "agreed" };
    case "waiting":
      return { word: "Pending", cls: "waiting" };
    case "lapsed":
      return { word: "Lapsed", cls: "lapsed" };
    case "undecided":
      return { word: "Undecided", cls: "open" };
    default:
      // Some places answered and the rest never decided. The server leaves
      // the word empty where none of the four holds, and drawing that as
      // "Undecided" claims nobody has looked at any of it.
      return { word: "Partly", cls: "waiting" };
  }
}
