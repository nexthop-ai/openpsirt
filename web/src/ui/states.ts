// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A place's decision state, in the words every screen says it in.
//
// One vocabulary, because a register, a comparison, the findings list and a
// document all state the same four words about the same fact. The server says
// them too, for the document it renders; that copy is the server's and moves
// with it.
const STATE_SAID: Record<string, string> = {
  undecided: "nobody has said",
  waiting: "waiting for a second person",
  agreed: "agreed",
  lapsed: "no longer stands",
};

// And how each is drawn, by the class names the rest of the interface uses.
const STATE_DRAWN: Record<string, string> = {
  undecided: "open",
  waiting: "waiting",
  agreed: "agreed",
  lapsed: "lapsed",
};

// The four, in the order a reader works down: what nobody has answered first.
export const STATES = ["undecided", "waiting", "agreed", "lapsed"] as const;

// One of the four, as a type, so an address that names something else cannot
// reach a query parameter that takes them.
export type Stands = (typeof STATES)[number];

// The class for the one case none of the four covers: some places answered and
// the rest never decided. The server leaves the word empty there. Drawn as
// waiting, because it is neither decided nor untouched.
const PARTLY_CLASS = "waiting";

// A table's entry for a word, asked through a guard: a server word naming a
// member every object inherits — `constructor` — is otherwise a function.
function own(table: Record<string, string>, word: string): string | undefined {
  return Object.hasOwn(table, word) ? table[word] : undefined;
}

// said is what a state is called, or a plain description of the one case none
// of the four covers: some places agreed and the rest never decided.
export function said(state: string | undefined): string {
  if (!state) return "part decided";
  return own(STATE_SAID, state) ?? state;
}

// drawn is the class it takes. A state this does not know is drawn as open, so
// it is visible rather than invisible.
export function drawn(state: string | undefined): string {
  if (!state) return PARTLY_CLASS;
  return own(STATE_DRAWN, state) ?? "open";
}
