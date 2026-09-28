// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The place somebody was on a page, kept so that coming back is coming back.
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

// The key the places are kept under, beside the other things kept per session:
// one object, mapping an address to how far down it and when.
const KEY = "openpsirt.place";

// The number of pages remembered. A handful, because what is wanted is the list
// somebody came from rather than every list they have ever read — and an
// unbounded map in storage is one that grows for as long as the tab is open.
const KEEP = 12;

type Place = { y: number; at: number };

// The places kept, checked rather than asserted: session storage is editable,
// and whatever comes out of it goes into a scroll call.
function kept(): Record<string, Place> {
  try {
    const raw: unknown = JSON.parse(window.sessionStorage.getItem(KEY) ?? "{}");
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
    const out: Record<string, Place> = {};
    for (const [address, place] of Object.entries(raw as Record<string, unknown>)) {
      if (typeof place !== "object" || place === null) continue;
      const { y, at } = place as { y?: unknown; at?: unknown };
      if (typeof y === "number" && typeof at === "number") out[address] = { y, at };
    }
    return out;
  } catch {
    return {};
  }
}

// markPlace records how far down a page somebody had scrolled.
//
// The most recent handful are kept, ordered by when each was marked rather
// than by the order a browser happens to list its storage in, so the list
// somebody just came from is never the one dropped.
export function markPlace(address: string, y: number) {
  try {
    const places = kept();
    const latest = Math.max(0, ...Object.values(places).map((place) => place.at));
    places[address] = { y: Math.round(y), at: latest + 1 };
    const newest = Object.entries(places)
      .sort(([, a], [, b]) => b.at - a.at)
      .slice(0, KEEP);
    window.sessionStorage.setItem(KEY, JSON.stringify(Object.fromEntries(newest)));
  } catch {
    // A browser that refuses storage loses a convenience and nothing else.
  }
}

// placeOf is where somebody was, or nothing where this page has no memory of
// them.
export function placeOf(address: string): number {
  const y = kept()[address]?.y;
  // Anything that is not a position is no position.
  return y !== undefined && Number.isFinite(y) && y >= 0 ? y : 0;
}

// forgetPlaces clears every remembered position.
//
// Called where the session's own things are cleared. Kept here beside the
// writers, so the clear and what it clears cannot drift apart.
export function forgetPlaces() {
  try {
    window.sessionStorage.removeItem(KEY);
  } catch {
    // Nothing to clear if storage was refused in the first place.
  }
}
