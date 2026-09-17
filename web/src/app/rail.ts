// Which groups of the rail are folded away.
//
// The rail asks for about 935 pixels of entries, which is taller than the
// window on most laptops. Giving it a scroll region of its own put a second
// scrollbar down the middle of the screen — a worse thing than the problem it
// solved — and letting it scroll with the page left the menu a thousand pixels
// above somebody reading the foot of a findings list.
//
// So it folds instead. "Manage" is shut to begin with: it is where somebody
// goes occasionally to grant a role or change a setting, rather than while
// working, and with it away the rail fits a laptop with room to spare.
//
// Kept in the browser, per person, the same rule as the look and saved
// filters: it changes what one person sees and nothing anybody else is shown.

const KEPT = "openpsirt.rail";
const SHUT_TO_BEGIN_WITH = ["manage"];

export function folded(): Set<string> {
  try {
    const kept = window.localStorage.getItem(KEPT);
    if (kept === null) return new Set(SHUT_TO_BEGIN_WITH);
    const names = JSON.parse(kept) as unknown;
    if (Array.isArray(names)) return new Set(names.filter((n) => typeof n === "string"));
  } catch {
    // A browser that refuses storage gets the shipped arrangement.
  }
  return new Set(SHUT_TO_BEGIN_WITH);
}

export function fold(shut: Set<string>) {
  try {
    window.localStorage.setItem(KEPT, JSON.stringify([...shut]));
  } catch {
    // The fold still applies for this page.
  }
}
