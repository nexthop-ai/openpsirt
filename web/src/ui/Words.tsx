import { useState } from "react";
import { notACredential } from "./noautofill";

// A filter somebody types into, holding as many words as they type.
//
// One box held one word, so a family of packages was three reads of the
// same list, and two of somebody's own tags could not be asked for at all.
// What is in it is chips, because a box that shows one value while narrowing
// by three is the thing the summary above the list exists to prevent.
//
// Any of them rather than all of them. A row has one component name, so
// "both" is a question with no answer; two of a person's own labels means
// either pile.

export function Words({
  label,
  hint,
  placeholder,
  words,
  onChange,
  // Words already in use here, offered while typing. A tag is free text and
  // the ones somebody used before are the ones they mean.
  offered,
  listId,
}: {
  label: string;
  hint?: string;
  placeholder?: string;
  words: string[];
  onChange: (words: string[]) => void;
  offered?: string[];
  listId?: string;
}) {
  const [typed, setTyped] = useState("");

  function add(word: string) {
    const said = word.trim();
    // Silently ignored rather than refused: adding a word that is already
    // there is not a mistake, it is somebody who forgot it was there.
    if (!said || words.includes(said)) {
      setTyped("");
      return;
    }
    onChange([...words, said]);
    setTyped("");
  }

  return (
    <label className="field">
      <span>{label}</span>
      {words.length > 0 && (
        <div className="words">
          {words.map((word) => (
            <button
              key={word}
              type="button"
              className="chip"
              aria-pressed
              title="Remove this one"
              onClick={() => onChange(words.filter((each) => each !== word))}
            >
              {word}
              <span aria-hidden>&times;</span>
            </button>
          ))}
        </div>
      )}
      <input
        {...notACredential}
        type="text"
        list={listId}
        placeholder={placeholder}
        value={typed}
        onChange={(event) => {
          // A comma ends a word, because somebody pasting a list types one.
          const said = event.target.value;
          if (said.endsWith(",")) add(said.slice(0, -1));
          else setTyped(said);
        }}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            // Kept off the form around it: this box adds a word, and the form
            // it sits in submits a search.
            event.preventDefault();
            add(typed);
          } else if (event.key === "Backspace" && typed === "" && words.length > 0) {
            onChange(words.slice(0, -1));
          }
        }}
        // What was half-typed and never entered would otherwise narrow
        // nothing while looking like it does.
        onBlur={() => add(typed)}
      />
      {listId && offered && (
        <datalist id={listId}>
          {offered.map((each) => (
            <option key={each} value={each} />
          ))}
        </datalist>
      )}
      {hint && <span className="hint">{hint}</span>}
    </label>
  );
}
