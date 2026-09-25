// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { useClickAway } from "./away";

// A filter as one button that names itself and what it is set to, and opens a
// short menu of its values.
//
// The label is inside the button rather than beside it. A label and its
// control laid out as two boxes wrap apart when the row runs out of room, so
// one filter ends up with its name above it while its neighbors have theirs
// beside them.
//
// Several values or one: a question like "undecided or waiting" is several
// answers at once, and one like "high and up" is a single step on a scale.
// The first draws checkboxes and stays open while they are ticked; the second
// draws a radio list and closes on a pick.

export type MenuOption = readonly [string, string];

export function FilterMenu({
  label,
  options,
  chosen,
  onChange,
  multi = false,
  anything = "Any",
}: {
  label: string;
  // The words the address carries, each with what it is called here. For one
  // value, the option whose word is empty is "not narrowed" and heads the
  // list; for several, nothing ticked is "not narrowed" and the empty word is
  // not offered.
  options: readonly MenuOption[];
  chosen: string[];
  onChange: (chosen: string[]) => void;
  multi?: boolean;
  // What the button says while nothing narrows.
  anything?: string;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const items = useRef<(HTMLButtonElement | null)[]>([]);
  const menuId = useId();

  const offered = multi ? options.filter(([word]) => word !== "") : options;
  const picked = offered.filter(([word]) => word !== "" && chosen.includes(word));
  const on = picked.length > 0;
  const says =
    picked.length === 0
      ? anything
      : picked.length === 1
        ? picked[0]![1]
        : `${picked[0]![1]} +${picked.length - 1}`;

  useClickAway(box, open, () => setOpen(false), false);

  useEffect(() => {
    if (open) items.current[active]?.focus();
  }, [open, active]);

  function show() {
    // Opened on what is picked, so a keyboard lands where the answer is.
    const at = offered.findIndex(([word]) =>
      word === "" ? chosen.length === 0 : chosen.includes(word),
    );
    setActive(Math.max(0, at));
    setOpen(true);
  }

  function close() {
    setOpen(false);
    trigger.current?.focus();
  }

  function choose(word: string) {
    if (!multi) {
      onChange(word === "" ? [] : [word]);
      close();
      return;
    }
    // Kept in the order offered, so the same selection is the same address
    // however it was reached.
    const next = new Set(chosen);
    if (next.has(word)) next.delete(word);
    else next.add(word);
    onChange(offered.map(([each]) => each).filter((each) => next.has(each)));
  }

  function onTriggerKey(event: KeyboardEvent<HTMLButtonElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      show();
    }
  }

  function onMenuKey(event: KeyboardEvent<HTMLDivElement>) {
    const last = offered.length - 1;
    const move: Record<string, number> = {
      ArrowDown: active === last ? 0 : active + 1,
      ArrowUp: active === 0 ? last : active - 1,
      Home: 0,
      End: last,
    };
    if (event.key in move) {
      event.preventDefault();
      setActive(move[event.key]!);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (event.key === "Tab") setOpen(false);
  }

  return (
    <div className="filtermenu" ref={box}>
      <button
        ref={trigger}
        type="button"
        className="filterbtn"
        data-on={on ? "yes" : undefined}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => (open ? setOpen(false) : show())}
        onKeyDown={onTriggerKey}
      >
        <span className="k">{label}</span>
        <span className="v">{says}</span>
        <span aria-hidden className="caret">
          ▾
        </span>
      </button>
      {open && (
        <div
          id={menuId}
          className="filterlist"
          role="menu"
          aria-label={label}
          onKeyDown={onMenuKey}
        >
          {offered.map(([word, name], i) => {
            const checked = word === "" ? chosen.length === 0 : chosen.includes(word);
            return (
              <button
                key={word || "any"}
                ref={(node) => {
                  items.current[i] = node;
                }}
                type="button"
                role={multi ? "menuitemcheckbox" : "menuitemradio"}
                aria-checked={checked}
                tabIndex={i === active ? 0 : -1}
                className="filteritem"
                onClick={() => {
                  setActive(i);
                  choose(word);
                }}
              >
                <span aria-hidden className={multi ? "box" : "dot"} />
                {name}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
