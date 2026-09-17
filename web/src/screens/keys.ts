// Working a list from the keyboard.
//
// The list is where a triager spends the day and it answered four keys in the
// whole application, one of them global. What is here is the smallest set that
// makes a page of findings workable without a pointer: move, open in place,
// close, and go to the finding itself.
//
// Kept apart from the screen because what a key means is a rule rather than a
// rendering, and because a rule about when a key must *not* fire is exactly
// the part worth pinning: a triager typing "j" into a justification does not
// mean "next row".

export type Meaning = "next" | "previous" | "open" | "close" | "openFull" | null;

// Whether what has focus takes typing, in which case no key here means
// anything. A contenteditable is the editor's own body, which is where a
// reasoning is written.
export function typingIn(element: Element | null): boolean {
  if (!element) return false;
  const tag = element.tagName.toUpperCase();
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  return (element as HTMLElement).isContentEditable === true;
}

// What a keypress means over the rows.
//
// A modifier makes it somebody else's: `Meta+K` is the browser's, and
// `Ctrl+N` is a new window. Only the bare key is ours.
export function meansFor(
  event: { key: string; ctrlKey?: boolean; metaKey?: boolean; altKey?: boolean },
  typing: boolean,
): Meaning {
  if (typing) return null;
  if (event.ctrlKey || event.metaKey || event.altKey) return null;
  switch (event.key) {
    case "j":
    case "ArrowDown":
      return "next";
    case "k":
    case "ArrowUp":
      return "previous";
    case "Enter":
      return "open";
    case "Escape":
      return "close";
    case "o":
      return "openFull";
    default:
      return null;
  }
}

// Where the cursor lands, given where it was and how many rows there are.
//
// It stops at each end rather than wrapping: a list is paged, so wrapping from
// the last row to the first says the page is the whole of it. Nothing selected
// and "next" is the first row, which is what a first keypress should do.
export function moved(at: number, by: 1 | -1, rows: number): number {
  if (rows === 0) return -1;
  if (at < 0) return by === 1 ? 0 : rows - 1;
  return Math.min(rows - 1, Math.max(0, at + by));
}
