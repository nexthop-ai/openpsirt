// How far a place has been decided, in the words every screen says it in.
//
// One vocabulary, because a register, a comparison and a document all state
// the same four words about the same fact — and three copies is three edits
// the day a fifth state exists, with the one nobody remembers reading in the
// vocabulary of the database.
//
// The server says them too, for the document it renders; that copy is the
// server's and moves with it.
export const STATE_SAID: Record<string, string> = {
  undecided: "nobody has said",
  waiting: "waiting for a second person",
  agreed: "agreed",
  lapsed: "no longer stands",
};

// And how each is drawn, by the class names the rest of the interface uses.
export const STATE_DRAWN: Record<string, string> = {
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

// said is what a state is called, or a plain description of the one case none
// of the four covers: some places agreed and the rest never decided.
export function said(state: string | undefined): string {
  if (!state) return "part decided";
  return STATE_SAID[state] ?? state;
}

// drawn is the class it takes, falling back to the open one — a state this
// does not know is visible rather than invisible.
export function drawn(state: string | undefined): string {
  return STATE_DRAWN[state ?? ""] ?? "open";
}
