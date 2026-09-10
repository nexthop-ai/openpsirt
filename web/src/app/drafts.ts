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
// **Every draft is under the identity that wrote it.** Browser storage is no
// more exposed than the application already open in the same profile — but
// only while the person at the browser is the person who typed the text.
// Signing out clears them; a session that quietly expired does not, so the
// identity in the key is what stops the next person to sign in on this browser
// from opening the same finding and being handed somebody else's reasoning.

// The namespace every draft lives under. Named the way the other things this
// application keeps in the browser are — the chosen theme and the scope
// somebody picked — and distinct enough from both that clearing drafts cannot
// take either with it.
const PREFIX = "openpsirt.draft.";

// Who the drafts on this page belong to. Set once the session is known and
// cleared when it is not, so a draft written before anybody was recognized is
// not silently attributed to whoever signs in next.
let writer = "";

// belongTo records whose drafts this page is reading and writing.
export function belongTo(identity: string | undefined) {
  writer = identity ?? "";
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
    if (text) window.localStorage.setItem(key, text);
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
  try {
    return window.localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
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
