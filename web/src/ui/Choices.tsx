import { useRef, useState } from "react";
import { useClickAway } from "./away";

// Several answers to one question, as a list of checkboxes behind a control
// that says what is ticked.
//
// A dropdown holding one value could not ask what people ask. "Undecided
// or waiting" is one question — everything nobody has finished with — and a
// select offered it as two lists to look at in turn. So is "nothing released
// or upstream declined", which is the whole population that needs a judgment
// rather than a version bump. Neither is expressible one word at a time.
//
// What is ticked is on the control, not behind it. A closed control that
// says "Any" while three boxes are ticked inside it is how a narrowed list
// comes to look like an unnarrowed one. One choice reads as itself, several
// read as a count, and the chips above the list name each of them.

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
  // What nothing ticked is called, which differs by question.
  anything?: string;
  // Drawn without its own label, for a toolbar that names it alongside the
  // other controls rather than above them.
  bare?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  useClickAway(box, open, () => setOpen(false));

  const offered = options.filter(([word]) => word !== "");
  const ticked = offered.filter(([word]) => chosen.includes(word));
  // One is named; several are counted. Naming several fits nothing and
  // truncating reads as a single value with a strange name.
  const says =
    ticked.length === 0
      ? anything
      : ticked.length === 1
        ? ticked[0]![1]
        : `${ticked.length} chosen`;

  function toggle(word: string, on: boolean) {
    // Kept in the order they are offered rather than the order they were
    // ticked, so the same selection makes the same address however it was
    // reached — two links that ask the same thing are the same link.
    const next = new Set(chosen);
    if (on) next.add(word);
    else next.delete(word);
    onChange(offered.map(([each]) => each).filter((each) => next.has(each)));
  }

  const control = (
    <div className="choices" ref={box}>
      <button
        type="button"
        className="choicesat"
        disabled={disabled}
        aria-expanded={open}
        aria-haspopup="true"
        data-on={ticked.length > 0 ? "yes" : undefined}
        onClick={() => setOpen(!open)}
      >
        <span>{says}</span>
        <span aria-hidden>{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div className="choicelist" role="group" aria-label={label}>
          {offered.map(([word, said]) => (
            <label key={word} className="check">
              <input
                type="checkbox"
                checked={chosen.includes(word)}
                onChange={(event) => toggle(word, event.target.checked)}
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
