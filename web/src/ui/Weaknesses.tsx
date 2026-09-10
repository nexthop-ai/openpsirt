import { notACredential } from "./noautofill";
import { useState } from "react";

// What kind of flaw it is, by the classification the world uses.
//
// **Suggested, never restricted.** The list below is the ones that come up
// most; anything may be typed. A picker that refused an identifier it had not
// heard of would refuse next year's, and the point of recording these is to
// make a set of findings comparable to things outside this deployment — which
// is served by recording what somebody meant, not by having an opinion.
//
// The names are here rather than fetched: they are a fixed vocabulary somebody
// else maintains, and a screen that could not offer them because a network
// call failed would be worse than one that offers a short list.
const COMMON: { id: string; name: string }[] = [
  { id: "CWE-79", name: "Cross-site scripting" },
  { id: "CWE-787", name: "Out-of-bounds write" },
  { id: "CWE-89", name: "SQL injection" },
  { id: "CWE-352", name: "Cross-site request forgery" },
  { id: "CWE-22", name: "Path traversal" },
  { id: "CWE-125", name: "Out-of-bounds read" },
  { id: "CWE-78", name: "OS command injection" },
  { id: "CWE-416", name: "Use after free" },
  { id: "CWE-862", name: "Missing authorization" },
  { id: "CWE-434", name: "Unrestricted upload of a dangerous file" },
  { id: "CWE-94", name: "Code injection" },
  { id: "CWE-20", name: "Improper input validation" },
  { id: "CWE-77", name: "Command injection" },
  { id: "CWE-287", name: "Improper authentication" },
  { id: "CWE-269", name: "Improper privilege management" },
  { id: "CWE-502", name: "Deserialization of untrusted data" },
  { id: "CWE-200", name: "Exposure of sensitive information" },
  { id: "CWE-863", name: "Incorrect authorization" },
  { id: "CWE-918", name: "Server-side request forgery" },
  { id: "CWE-119", name: "Buffer overflow" },
  { id: "CWE-476", name: "Null pointer dereference" },
  { id: "CWE-798", name: "Hard-coded credentials" },
  { id: "CWE-190", name: "Integer overflow" },
  { id: "CWE-400", name: "Uncontrolled resource consumption" },
  { id: "CWE-306", name: "Missing authentication for a critical function" },
];

const NAMES = new Map(COMMON.map((c) => [c.id, c.name]));

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
      <label htmlFor="cwe-typed">What kind of flaw</label>
      <p className="hint" style={{ marginTop: 0 }}>
        Optional, and more than one is fine. It is what makes a set of findings comparable to
        anything outside this deployment.
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
              {NAMES.has(id) && <span className="hint">{NAMES.get(id)}</span>}
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
      <span className="hint">
        Anything may be typed — the suggestions are the ones that come up most, not the only ones
        allowed.
      </span>
    </div>
  );
}
