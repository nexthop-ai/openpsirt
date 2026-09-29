// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { notACredential } from "./noautofill";

// A filter somebody types into, holding as many words as they type.
//
// Several words, so a family of packages is one read of the list and two of
// somebody's own tags can be asked for together. It holds chips, because a box
// that shows one value while narrowing by three is the thing the summary above
// the list exists to prevent.
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
  named,
  onTyping,
}: {
  label: string;
  hint?: string;
  placeholder?: string;
  words: string[];
  onChange: (words: string[]) => void;
  offered?: string[];
  listId?: string;
  // What a word is called and what it is called in full, for a word that is
  // an identifier: drawn beside it on its chip and its offer, the full name
  // on hover.
  named?: (word: string) => { called: string; full?: string } | undefined;
  // What is being typed, for a box whose offers are searched as it is.
  onTyping?: (typed: string) => void;
}) {
  const [typed, setTypedHere] = useState("");
  const setTyped = (next: string) => {
    setTypedHere(next);
    onTyping?.(next);
  };

  // Everything typed or pasted, split where a comma ends a word: the words it
  // finished, and the part still being typed.
  function typing(said: string) {
    const { finished, left } = pasted(said, words);
    if (finished.length > 0) onChange([...words, ...finished]);
    setTyped(left);
  }

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
              title={
                named?.(word)?.full ? `${named(word)?.full}. Remove this one` : "Remove this one"
              }
              onClick={() => onChange(words.filter((each) => each !== word))}
            >
              {word}
              {named?.(word)?.called ? ` ${named(word)?.called}` : ""}
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
        // A comma ends a word, because somebody pasting a list types one.
        onChange={(event) => typing(event.target.value)}
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
        // A word half-typed and never entered would otherwise narrow
        // nothing while looking like it does.
        onBlur={() => add(typed)}
      />
      {listId && offered && (
        <datalist id={listId}>
          {offered.map((each) => (
            <option key={each} value={each} label={named?.(each)?.called} />
          ))}
        </datalist>
      )}
      {hint && <span className="hint">{hint}</span>}
    </label>
  );
}

// The words a comma finished in what was typed, without any already held or
// any repeated, and what is left after the last comma.
export function pasted(
  said: string,
  held: readonly string[],
): { finished: string[]; left: string } {
  const pieces = said.split(",");
  const left = pieces.pop() ?? "";
  const finished: string[] = [];
  for (const piece of pieces) {
    const word = piece.trim();
    if (word && !held.includes(word) && !finished.includes(word)) finished.push(word);
  }
  return { finished, left };
}
