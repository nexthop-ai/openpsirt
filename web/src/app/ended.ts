// Whether the session ended under somebody who is still on a screen.
//
// A 401 from a read that a screen is waiting on already resolves to "nobody is
// signed in", and the sign-in page takes over. A 401 from a *write* is
// different: the screen is drawn, the person is looking at it, and quite
// possibly halfway through typing into it. Replacing all of that with a sign-in
// page loses their place for no reason — the words are safe either way, because
// a draft is written as it is typed, but the finding they were reading, the
// filters they had set and the row they had open are not.
//
// So it is recorded here and offered over the screen rather than instead of
// it.
//
// A module rather than React state because the thing that notices is the query
// client, which is created outside the tree and has no way to reach into it.

let ended = false;
const watching = new Set<() => void>();

// Ended records that the session has gone.
export function sessionEnded() {
  if (ended) return;
  ended = true;
  for (const tell of watching) tell();
}

// Resumed clears it, for the case somebody signs in again without the page
// reloading. Nothing does that today — every way back through a provider is a
// redirect — and it exists so that the flag is not a one-way door if one ever
// does.
export function sessionResumed() {
  if (!ended) return;
  ended = false;
  for (const tell of watching) tell();
}

// subscribe and snapshot are what useSyncExternalStore needs.
export function subscribe(tell: () => void): () => void {
  watching.add(tell);
  return () => watching.delete(tell);
}

export function snapshot(): boolean {
  return ended;
}
