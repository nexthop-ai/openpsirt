// Unsent text, kept where a closed tab, a crashed browser or a sleeping laptop
// cannot take it.
//
// Two rules make this safe to keep at all, and both are here rather than at
// each call site, because a control spelled once at six of them is a control
// that is missing at the seventh.
//
// **Every draft is under one prefix**, so "clear them all" is one loop over a
// namespace rather than a list of key shapes somebody has to keep in step with
// the screens.
//
// **Every draft is under the identity that wrote it**, and somebody else
// signing in on this browser clears what is not theirs. That is what stops the
// next person opening the same finding and being handed somebody else's
// reasoning.
//
// **And every draft has an age.** Signing out clears them; a session that
// quietly expired does not, and browser storage outlives every session and
// needs no credential to read — so text about an undisclosed finding, written
// on a shared machine, sat there for anybody who opened the tools. Anything
// past the age below goes on the first read of a page load.
//
// **What that still leaves**, said rather than glossed: a draft written and
// abandoned inside the window is readable by whoever reaches the profile
// before it lapses. The window is what bounds that, and clearing on sign-out
// is what ends it for somebody who leaves deliberately.

// The namespace every draft lives under. Named the way the other things this
// application keeps in the browser are — the chosen theme and the scope
// somebody picked — and distinct enough from both that clearing drafts cannot
// take either with it.
const PREFIX = "openpsirt.draft.";

// How long a draft outlives being written.
//
// A day, which is the span a piece of unsent triage text is plausibly still
// wanted over — somebody writing a justification before a meeting and
// finishing it after. Past it the text is much more likely to be forgotten
// than resumed, and forgotten text in storage that outlives every session is
// what this bound is for.
const KEEP_FOR = 24 * 60 * 60 * 1000;

// Who the drafts on this page belong to. Set once the session is known and
// cleared when it is not, so a draft written before anybody was recognized is
// not silently attributed to whoever signs in next.
let writer = "";

// belongTo records whose drafts this page is reading and writing, and takes
// away what is not theirs.
//
// A session that lapsed left its drafts behind, and the identity in the key
// only stopped them being read back into the same form — it did not stop them
// being in the storage. Whoever is here now is the only person whose text
// belongs on this browser.
export function belongTo(identity: string | undefined) {
  writer = identity ?? "";
  if (writer) sweep();
}

// sweep drops every draft that is somebody else's or older than the window.
//
// Run when a session is recognized rather than on a timer: a page load is
// when the previous person's text is still there and the current person's is
// about to be written.
function sweep() {
  try {
    const going: string[] = [];
    const mine = PREFIX + writer + ":";
    const now = Date.now();
    for (let i = 0; i < window.localStorage.length; i++) {
      const key = window.localStorage.key(i);
      if (!key || !key.startsWith(PREFIX)) continue;
      if (!key.startsWith(mine)) {
        going.push(key);
        continue;
      }
      const held = read(key);
      if (!held || now - held.at > KEEP_FOR) going.push(key);
    }
    // Collected first and removed after, for the reason forgetAll does it.
    for (const key of going) window.localStorage.removeItem(key);
  } catch {
    // A browser that refuses storage has nothing to sweep.
  }
}

// read is one stored draft, or nothing where it is unreadable or shaped the
// way drafts were shaped before they carried a time.
function read(key: string): { text: string; at: number } | null {
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    const held: unknown = JSON.parse(raw);
    if (
      typeof held === "object" &&
      held !== null &&
      typeof (held as { text?: unknown }).text === "string" &&
      typeof (held as { at?: unknown }).at === "number"
    ) {
      return held as { text: string; at: number };
    }
    return null;
  } catch {
    return null;
  }
}

// keyFor is where one draft lives: the namespace, whose it is, and what it is
// about. An empty identity gives an empty key, which every function here reads
// as "do not keep this" — text typed before anybody is recognized has nowhere
// safe to go.
function keyFor(about: string | undefined): string {
  if (!about || !writer) return "";
  return PREFIX + writer + ":" + about;
}

// keep stores text, or removes the draft when there is none left to keep.
export function keep(about: string | undefined, text: string) {
  const key = keyFor(about);
  if (!key) return;
  try {
    // With the moment it was written, which is what the window is measured
    // from. A draft edited again is a draft still wanted, so the clock
    // restarts rather than running from when it was first typed.
    if (text) window.localStorage.setItem(key, JSON.stringify({ text, at: Date.now() }));
    else window.localStorage.removeItem(key);
  } catch {
    // A browser that refuses storage is not a reason to fail. The draft is a
    // convenience; the text in front of somebody is the real thing.
  }
}

// restore reads back what was left behind, or nothing.
export function restore(about: string | undefined): string {
  const key = keyFor(about);
  if (!key) return "";
  const held = read(key);
  if (!held) return "";
  if (Date.now() - held.at > KEEP_FOR) {
    // Past the window. Taken away as it is asked for, so a draft nobody came
    // back to does not wait for the next sign-in to go.
    try {
      window.localStorage.removeItem(key);
    } catch {
      // Nothing to clear if storage was refused in the first place.
    }
    return "";
  }
  return held.text;
}

// forget clears one draft once its text has actually been accepted. Called on
// success only: a failed submission keeps what somebody wrote.
export function forget(about: string | undefined) {
  const key = keyFor(about);
  if (!key) return;
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Nothing to clear if storage was refused in the first place.
  }
}

// forgetAll clears every draft this browser holds, whoever wrote them.
//
// Called on sign-out, which is the control the local draft rests on: drafts
// hold triage text, private findings included, and text surviving a sign-out
// would be exposed in a way the application itself is not. Every writer's, not
// only the one signing out — a draft left by an earlier session is exactly the
// one nobody would think to clear.
export function forgetAll() {
  try {
    const going: string[] = [];
    for (let i = 0; i < window.localStorage.length; i++) {
      const key = window.localStorage.key(i);
      if (key && key.startsWith(PREFIX)) going.push(key);
    }
    // Collected first and removed after: removing while walking the store
    // renumbers what is left, and every other key shifts under the cursor.
    for (const key of going) window.localStorage.removeItem(key);
  } catch {
    // As above.
  }
}
