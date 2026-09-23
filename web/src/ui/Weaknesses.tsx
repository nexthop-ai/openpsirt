// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { notACredential } from "./noautofill";
import { useState } from "react";
import { COMMON, nameOf } from "./cwe";

// The picker for what kind of flaw something is. The vocabulary, the names and
// where to read about one live beside it in `cwe.ts`, because the finding
// screen names them too and two lists of names is two lists that disagree.

export function Weaknesses({
  chosen,
  onChange,
}: {
  chosen: string[];
  onChange: (next: string[]) => void;
}) {
  const [typed, setTyped] = useState("");

  function add(id: string) {
    const clean = id.trim().toUpperCase();
    if (clean === "" || chosen.includes(clean)) return;
    onChange([...chosen, clean]);
    setTyped("");
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
              {nameOf(id) && <span className="hint">{nameOf(id)}</span>}
            </li>
          ))}
        </ul>
      )}

      <input
        id="cwe-typed"
        {...notACredential}
        type="text"
        list="cwe-common"
        value={typed}
        placeholder="CWE-125, or pick one"
        onChange={(event) => setTyped(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            add(typed);
          }
        }}
        onBlur={() => typed.trim() !== "" && add(typed)}
      />
      <datalist id="cwe-common">
        {COMMON.map((each) => (
          <option key={each.id} value={each.id}>
            {each.name}
          </option>
        ))}
      </datalist>
      <span className="hint">Anything may be typed. These are the most common.</span>
    </div>
  );
}
