// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useEffectEvent, type RefObject } from "react";

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
  // The listener calls the close of the latest render without being
  // re-attached for it, so a close holding state never acts on a stale copy,
  // and a caller passing a fresh arrow each render costs nothing.
  const dismiss = useEffectEvent(close);

  useEffect(() => {
    if (!open) return;
    function away(event: MouseEvent) {
      if (box.current && !box.current.contains(event.target as Node)) dismiss();
    }
    function key(event: KeyboardEvent) {
      if (event.key === "Escape") dismiss();
    }
    document.addEventListener("mousedown", away);
    if (onEscape) document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", away);
      if (onEscape) document.removeEventListener("keydown", key);
    };
  }, [box, open, onEscape]);
}
