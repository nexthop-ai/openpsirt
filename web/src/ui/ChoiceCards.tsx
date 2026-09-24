// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useRef, type KeyboardEvent } from "react";

// One answer to a question whose answer has a consequence, as a card per
// option with what picking it does inside the card. The consequence is read
// before the choice is made rather than after it.
//
// A radio group to assistive technology and to the keyboard: one tab stop,
// the arrow keys move through the options and pick as they go, and Home and
// End reach the ends. With nothing picked the first option takes the stop.

export type ChoiceCard<T extends string> = {
  value: T;
  label: string;
  // What picking it does, in a few words.
  note?: string;
};

// The option a key moves to from the one at `at`, or undefined for a key the
// group does not handle. The arrows wrap, as a radio group's do.
export function stepFor(key: string, at: number, count: number): number | undefined {
  if (count === 0) return undefined;
  switch (key) {
    case "ArrowRight":
    case "ArrowDown":
      return at < 0 ? 0 : (at + 1) % count;
    case "ArrowLeft":
    case "ArrowUp":
      return at < 0 ? count - 1 : (at - 1 + count) % count;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return undefined;
  }
}

export function ChoiceCards<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: readonly ChoiceCard<T>[];
  value: T | "";
  onChange: (value: T) => void;
}) {
  const cards = useRef<(HTMLButtonElement | null)[]>([]);
  const at = options.findIndex((each) => each.value === value);

  const onKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const next = stepFor(event.key, at, options.length);
    if (next === undefined) return;
    event.preventDefault();
    const option = options[next];
    if (!option) return;
    onChange(option.value);
    cards.current[next]?.focus();
  };

  return (
    <div className="choice-cards" role="radiogroup" aria-label={label} onKeyDown={onKey}>
      {options.map((each, index) => {
        const picked = each.value === value;
        return (
          <button
            key={each.value}
            ref={(element) => {
              cards.current[index] = element;
            }}
            type="button"
            role="radio"
            aria-checked={picked}
            tabIndex={picked || (at < 0 && index === 0) ? 0 : -1}
            className="choice-card"
            onClick={() => onChange(each.value)}
          >
            <span className="dot" aria-hidden="true" />
            <span>
              <b>{each.label}</b>
              {each.note && <span className="note">{each.note}</span>}
            </span>
          </button>
        );
      })}
    </div>
  );
}
