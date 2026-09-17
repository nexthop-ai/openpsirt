import { notACredential } from "./noautofill";
import { useClickAway } from "./away";
import { useRef, useState } from "react";

// A name typed against a list the server holds, with what matches shown.
//
// The browser's own `datalist` was doing this and nobody could tell: it has no
// affordance at all — no arrow, no list until two characters are typed, and
// nothing to say whether anything matched. A name typed from memory against an
// inventory of thousands is the input in this tool most likely to be wrong, and
// being refused after typing is a worse way to find that out than being shown
// what exists while typing.
//
// **It does not restrict.** What is offered comes from what the deployment
// holds, and the server is still the thing that refuses a name it does not
// know — a control that would only accept what it had already loaded would be
// a second, worse copy of that rule, and would refuse a name that arrived
// between the two requests.

export function Suggest({
  id,
  value,
  onChange,
  onPick,
  options,
  disabled,
  placeholder,
  loading,
  from = 2,
  label,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  // Called when one of the offered names is chosen rather than typed, where
  // that is a different act — picking resolves the field, typing does not.
  onPick?: (value: string) => void;
  options: string[];
  disabled?: boolean;
  placeholder?: string;
  loading?: boolean;
  // How many characters before anything is looked up. A list of thousands is
  // searched rather than loaded, and one letter matches most of it.
  from?: number;
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  const [at, setAt] = useState(-1);
  const box = useRef<HTMLDivElement>(null);

  // Closing on a click anywhere else, which is what a list over the page has
  // to do. Blur alone is not enough: picking is a click inside, and a blur
  // handler that closed first would take the list away before the click landed.
  useClickAway(box, open, () => setOpen(false), false);

  const asked = value.trim().length >= from;
  const showing = open && asked;

  function choose(name: string) {
    onChange(name);
    onPick?.(name);
    setOpen(false);
    setAt(-1);
  }

  return (
    <div className="suggest" ref={box}>
      <input
        id={id}
        {...notACredential}
        type="text"
        role="combobox"
        aria-expanded={showing}
        aria-autocomplete="list"
        aria-label={label}
        autoComplete="off"
        value={value}
        disabled={disabled}
        placeholder={placeholder}
        onChange={(event) => {
          onChange(event.target.value);
          setOpen(true);
          setAt(-1);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            setOpen(false);
            return;
          }
          if (!showing || options.length === 0) return;
          if (event.key === "ArrowDown") {
            event.preventDefault();
            setAt((was) => (was + 1) % options.length);
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            setAt((was) => (was <= 0 ? options.length - 1 : was - 1));
          } else if (event.key === "Enter" && at >= 0) {
            event.preventDefault();
            choose(options[at] ?? value);
          }
        }}
      />
      {showing && (
        <ul className="suggestions" role="listbox">
          {loading ? (
            <li className="hint">Looking…</li>
          ) : options.length === 0 ? (
            // Said rather than left blank. "Nothing here is called that" is
            // the answer somebody needs before they send it and are refused.
            //
            // Two answers, because an empty box is not a search that found
            // nothing. A control opening on focus offers the whole list, so
            // where the deployment holds none it was reporting a search
            // nobody had made.
            <li className="hint">
              {value.trim() === ""
                ? "There are none of these yet."
                : "Nothing here is called that."}
            </li>
          ) : (
            options.map((name, i) => (
              <li key={name}>
                <button
                  type="button"
                  role="option"
                  aria-selected={i === at}
                  className={i === at ? "on" : ""}
                  onMouseEnter={() => setAt(i)}
                  onClick={() => choose(name)}
                >
                  {name}
                </button>
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  );
}
