// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { useClickAway } from "./away";
import { moved } from "./choices";

// The open list behind a filter control, and the keys that work it: an arrow
// on the control opens it on the item `startAt` names; the arrows, Home and
// End move between the items; Escape closes it and returns to the control;
// Tab closes it and lets focus move on, so a list never stays drawn over the
// control after it. A press outside closes it, and Escape anywhere where
// `escapeAnywhere` is set.
export function useMenu<Item extends HTMLElement>({
  count,
  startAt,
  escapeAnywhere = true,
}: {
  count: number;
  startAt: () => number;
  escapeAnywhere?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const items = useRef<(Item | null)[]>([]);

  useClickAway(box, open, () => setOpen(false), escapeAnywhere);

  useEffect(() => {
    if (open) items.current[active]?.focus();
  }, [open, active]);

  function show() {
    setActive(Math.max(0, startAt()));
    setOpen(true);
  }

  function close() {
    setOpen(false);
    trigger.current?.focus();
  }

  function toggle() {
    if (open) setOpen(false);
    else show();
  }

  function onTriggerKey(event: KeyboardEvent<HTMLButtonElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      show();
    }
  }

  function onListKey(event: KeyboardEvent<HTMLDivElement>) {
    const next = moved(event.key, active, count);
    if (next !== undefined) {
      event.preventDefault();
      setActive(next);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (event.key === "Tab") setOpen(false);
  }

  return { open, active, setActive, box, trigger, items, close, toggle, onTriggerKey, onListKey };
}
