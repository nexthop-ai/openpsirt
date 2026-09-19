import { useEffect, type RefObject } from "react";

// Closing something open when the reader's attention leaves it.
//
// The behavior a list drawn over the page needs, where blur alone is not
// enough:
// picking an item is a click inside, and a blur handler that closed first
// would take the list away before the click landed. So it listens for a press
// anywhere outside the box, and for Escape where the caller asks for it.
//
// One listener rather than a copy per screen. It is easy to write and the
// cleanup is easy to get wrong — a copy that forgets to remove it leaves a
// handler on the document for the life of the page, closing something that is
// no longer there.
export function useClickAway(
  box: RefObject<HTMLElement | null>,
  open: boolean,
  close: () => void,
  onEscape = true,
) {
  useEffect(() => {
    if (!open) return;
    function away(event: MouseEvent) {
      if (box.current && !box.current.contains(event.target as Node)) close();
    }
    function key(event: KeyboardEvent) {
      if (event.key === "Escape") close();
    }
    document.addEventListener("mousedown", away);
    if (onEscape) document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", away);
      if (onEscape) document.removeEventListener("keydown", key);
    };
    // close is a setter or a stable callback at every call site; listing it
    // would re-attach the listener on every render of the component that
    // draws the box.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, onEscape]);
}
