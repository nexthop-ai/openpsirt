// Where somebody was on a page, kept so that coming back is coming back.
//
// A browser restores scroll on a real navigation and an application like this
// one never makes one. Going into a finding and pressing back rebuilds the
// list at the top of it: eighteen rows above where somebody was, on the screen
// whose whole use is working down a list one row at a time. The address is
// restored, the filters are restored, and the place in the list is the one
// thing that cannot be re-derived from the address.
//
// Kept in the session store rather than in memory: a reload is the other way
// somebody arrives back at a list they were reading, and a module variable
// does not survive one. Cleared with everything else that belongs to the
// session, so the next person on this browser does not land in the middle of
// somebody else's page.

// The namespace, beside the other two things kept per session.
const PREFIX = "openpsirt.place.";

// How many pages are remembered. A handful, because what is wanted is the list
// somebody came from rather than every list they have ever read — and an
// unbounded map in storage is one that grows for as long as the tab is open.
const KEEP = 12;

// where records how far down a page somebody had scrolled.
//
// The address without its hash, because a hash is a place within a page and
// this is a place within a list: two addresses differing only by an anchor are
// one list read in one position.
export function markPlace(address: string, y: number) {
  try {
    window.sessionStorage.setItem(PREFIX + address, String(Math.round(y)));
    trim();
  } catch {
    // A browser that refuses storage loses a convenience and nothing else.
  }
}

// placeOf is where somebody was, or nothing where this page has no memory of
// them.
export function placeOf(address: string): number {
  try {
    const kept = window.sessionStorage.getItem(PREFIX + address);
    if (kept === null) return 0;
    const y = Number(kept);
    // Anything that is not a position is no position. The value goes straight
    // into a scroll call, and session storage is editable.
    return Number.isFinite(y) && y >= 0 ? y : 0;
  } catch {
    return 0;
  }
}

// forgetPlaces clears every remembered position.
//
// Called where the session's own things are cleared. Kept here beside the
// writers, so the clear and what it clears cannot drift apart.
export function forgetPlaces() {
  try {
    const going: string[] = [];
    for (let i = 0; i < window.sessionStorage.length; i++) {
      const key = window.sessionStorage.key(i);
      if (key?.startsWith(PREFIX)) going.push(key);
    }
    // Collected first and removed after: removing inside the walk moves every
    // index after it, so half of them are stepped over.
    for (const key of going) window.sessionStorage.removeItem(key);
  } catch {
    // Nothing to clear if storage was refused in the first place.
  }
}

// trim keeps the most recent handful and drops the rest.
//
// Oldest-first is not knowable from the store, so what is dropped is whatever
// the walk reaches past the bound. The cost of dropping the wrong one is one
// list opening at the top, which is where it opened before any of this.
function trim() {
  const keys: string[] = [];
  for (let i = 0; i < window.sessionStorage.length; i++) {
    const key = window.sessionStorage.key(i);
    if (key?.startsWith(PREFIX)) keys.push(key);
  }
  for (const key of keys.slice(0, Math.max(0, keys.length - KEEP))) {
    window.sessionStorage.removeItem(key);
  }
}
