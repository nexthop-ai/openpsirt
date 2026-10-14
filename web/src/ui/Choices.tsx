// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { useClickAway } from "./away";
import { moved, summary, toggled } from "./choices";

// Several answers to one question, as a list of checkboxes behind a control
// that says what is ticked.
//
// A dropdown holding one value could not ask what people ask. "Undecided
// or waiting" is one question — everything nobody has finished with — and a
// select offered it as two lists to look at in turn. So is "nothing released
// or upstream declined", which is the whole population that needs a judgment
// rather than a version bump. Neither is expressible one word at a time.
//
// The ticked values sit on the control, not behind it. A closed control that
// says "Any" while three boxes are ticked inside it is how a narrowed list
// comes to look like an unnarrowed one. One choice reads as itself, several
// as the first and how many more, and the chips above the list name each of
// them.
//
// Operated from the keyboard as the filter bar's menus are: an arrow key on
// the control opens it, the arrows, Home and End move between the boxes, and
// Escape closes it and returns to the control.

export type Choice = readonly [string, string];

export function Choices({
  label,
  hint,
  options,
  chosen,
  onChange,
  disabled,
  anything = "Any",
  bare,
}: {
  label: string;
  hint?: string;
  // The words the server takes, each with what it is called here. An option
  // whose word is empty is not offered: "any" is nothing ticked, not a value.
  options: readonly Choice[];
  chosen: string[];
  onChange: (chosen: string[]) => void;
  disabled?: boolean;
  // The label for nothing ticked, which differs by question.
  anything?: string;
  // Drawn without its own label, for a toolbar that names it alongside the
  // other controls rather than above them.
  bare?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const boxes = useRef<(HTMLInputElement | null)[]>([]);

  useClickAway(box, open, () => setOpen(false));

  useEffect(() => {
    if (open) boxes.current[active]?.focus();
  }, [open, active]);

  const offered = options.filter(([word]) => word !== "");
  const ticked = offered.filter(([word]) => chosen.includes(word));
  const says = summary(ticked, anything);

  function show() {
    // Opened on the first box ticked, so a keyboard lands where the answer is.
    setActive(
      Math.max(
        0,
        offered.findIndex(([word]) => chosen.includes(word)),
      ),
    );
    setOpen(true);
  }

  function onTriggerKey(event: KeyboardEvent<HTMLButtonElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      show();
    }
  }

  function onListKey(event: KeyboardEvent<HTMLDivElement>) {
    const next = moved(event.key, active, offered.length);
    if (next !== undefined) {
      event.preventDefault();
      setActive(next);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      trigger.current?.focus();
    }
  }

  const control = (
    <div className="choices" ref={box}>
      <button
        ref={trigger}
        type="button"
        className="choicesat"
        disabled={disabled}
        aria-expanded={open}
        aria-haspopup="true"
        data-on={ticked.length > 0 ? "yes" : undefined}
        onClick={() => (open ? setOpen(false) : show())}
        onKeyDown={onTriggerKey}
      >
        <span>{says}</span>
        <span aria-hidden>{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div className="choicelist" role="group" aria-label={label} onKeyDown={onListKey}>
          {offered.map(([word, said], i) => (
            <label key={word} className="check">
              <input
                ref={(node) => {
                  boxes.current[i] = node;
                }}
                type="checkbox"
                checked={chosen.includes(word)}
                onFocus={() => setActive(i)}
                onChange={(event) => onChange(toggled(offered, chosen, word, event.target.checked))}
              />
              <span>{said}</span>
            </label>
          ))}
          {ticked.length > 0 && (
            <button type="button" className="linkish" onClick={() => onChange([])}>
              Clear
            </button>
          )}
        </div>
      )}
    </div>
  );

  if (bare) return control;
  return (
    <label className="field">
      <span>{label}</span>
      {control}
      {hint && <span className="hint">{hint}</span>}
    </label>
  );
}
