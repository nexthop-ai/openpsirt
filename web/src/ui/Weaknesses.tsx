// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { notACredential } from "./noautofill";
import { useState } from "react";
import { asWeakness, called, MOST_WEAKNESSES, useWeaknessNames, useWeaknessSearch } from "./cwe";

// The picker for what kind of flaw something is. What is offered while typing
// is the server's search over both lists of names, by number or by words, most
// common first; the vocabulary and where to read about one live in `cwe.ts`.

export function Weaknesses({
  chosen,
  onChange,
}: {
  chosen: string[];
  onChange: (next: string[]) => void;
}) {
  const [typed, setTyped] = useState("");
  const [problem, setProblem] = useState("");
  const offered = useWeaknessSearch(typed).data ?? [];
  const names = useWeaknessNames(chosen);

  function add(id: string) {
    if (id.trim() === "") return;
    const clean = asWeakness(id);
    if (clean === null) {
      setProblem("Pick one, or type CWE- and a number, like CWE-125.");
      return;
    }
    if (chosen.includes(clean)) {
      setTyped("");
      setProblem("");
      return;
    }
    if (chosen.length >= MOST_WEAKNESSES) {
      setProblem(`${MOST_WEAKNESSES} at most.`);
      return;
    }
    onChange([...chosen, clean]);
    setTyped("");
    setProblem("");
  }

  return (
    <div className="field">
      <label htmlFor="cwe-typed">Kind of flaw</label>
      <p className="hint" style={{ marginTop: 0 }}>
        Optional. More than one is fine.
      </p>

      {chosen.length > 0 && (
        <ul className="refs" style={{ margin: "0 0 8px" }}>
          {chosen.map((id) => (
            <li key={id}>
              <button
                type="button"
                className="chip"
                title="Remove it"
                onClick={() => onChange(chosen.filter((each) => each !== id))}
              >
                {id} ×
              </button>
              {called(names.get(id)) && (
                <span className="hint" title={names.get(id)?.name}>
                  {called(names.get(id))}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}

      <input
        id="cwe-typed"
        {...notACredential}
        type="text"
        list="cwe-offered"
        value={typed}
        placeholder="CWE-125, or words to search"
        onChange={(event) => setTyped(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            add(typed);
          }
        }}
        onBlur={() => typed.trim() !== "" && add(typed)}
      />
      <datalist id="cwe-offered">
        {offered.map((each) => (
          <option key={each.id} value={each.id} label={called(each)}>
            {called(each)}
          </option>
        ))}
      </datalist>
      {problem !== "" && (
        <span className="hint" role="alert">
          {problem}
        </span>
      )}
      <span className="hint">By number or by name. The most common come first.</span>
    </div>
  );
}
