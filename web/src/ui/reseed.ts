import { useState } from "react";

// Local state that has to start again when the thing it was seeded from moves.
//
// A panel opens and its fields go back to the scope. An address changes and the
// pending pick follows it. A vector is pasted in whole and the metrics light up
// to match. In each of those the state is somebody's to edit afterwards, so it
// cannot simply be derived — and it is wrong the moment the seed changes.
//
// **Seeded while rendering, not after painting.** An effect that writes state
// runs after the browser has already drawn the old value, so the frame between
// the two shows a form seeded from the last thing somebody looked at. React
// re-renders before the paint instead, and the stale frame never exists.
//
// The alternative is a key on the element, which throws away every piece of
// state it holds rather than the ones being re-seeded. That is the right answer
// where starting again means all of it, and the wrong one wherever something
// beside the seeded fields has to survive — a panel that stays open across a
// pick, a metric list that must not collapse when the last metric completes the
// vector.
export function useReseed(from: string, seed: () => void): void {
  const [seen, setSeen] = useState(from);
  if (seen !== from) {
    setSeen(from);
    seed();
  }
}
