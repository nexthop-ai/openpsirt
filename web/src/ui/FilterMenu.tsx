// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";
import { summary, toggled } from "./choices";
import { useMenu } from "./menu";

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
  const menuId = useId();

  const offered = multi ? options.filter(([word]) => word !== "") : options;
  const picked = offered.filter(([word]) => word !== "" && chosen.includes(word));
  const on = picked.length > 0;
  const says = summary(picked, anything);

  // Opened on what is picked, so a keyboard lands where the answer is.
  const menu = useMenu<HTMLButtonElement>({
    count: offered.length,
    startAt: () =>
      offered.findIndex(([word]) => (word === "" ? chosen.length === 0 : chosen.includes(word))),
    escapeAnywhere: false,
  });
  const { open, active, setActive, box, trigger, items, close, onTriggerKey } = menu;

  function choose(word: string) {
    if (!multi) {
      onChange(word === "" ? [] : [word]);
      close();
      return;
    }
    onChange(toggled(offered, chosen, word, !chosen.includes(word)));
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
        onClick={menu.toggle}
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
          onKeyDown={menu.onListKey}
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
