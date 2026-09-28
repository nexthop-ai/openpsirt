// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { drawn } from "./states";

// A group's decision state, as the one word a row shows. The findings list and
// the issue screen show the same rows and read it from here; the class comes
// from the vocabulary a comparison and the register draw with, so one state
// takes one color on every screen.
//
// The five words the state filter takes, plus the two states a filter has no
// name for: a claim sent back to its author, which is what the proposer is
// looking for in a list, and the empty state — some places answered and the
// rest not, which is neither decided nor undecided and has to say so.
export type Decided = { word: string; cls: string };

export function decidedAs(state?: string, sentBack?: boolean): Decided {
  if (sentBack) return { word: "Rejected", cls: "lapsed" };
  const cls = drawn(state);
  switch (state) {
    case "agreed":
      return { word: "Decided", cls };
    case "waiting":
      return { word: "Pending", cls };
    case "lapsed":
      return { word: "Lapsed", cls };
    case "undecided":
      return { word: "Undecided", cls };
    default:
      // Some places answered and the rest never decided. The server leaves
      // the word empty where none of the four holds, and drawing that as
      // "Undecided" claims nobody has looked at any of it.
      return { word: "Partly", cls };
  }
}
