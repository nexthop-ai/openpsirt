// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Outward } from "./Outward";
import { nameOf, readAbout, unclassified } from "./cwe";

// The kind of flaw, as a reader can use it.
//
// A finding showed the first identifier and dropped the rest, as a bare
// number: "CWE-401" is not something anybody knows, and the four most common
// in a real kernel backlog — a memory leak, a race, improper locking, a double
// free — were all unnamed. Every one is shown, the common ones are named, and
// each links to where it is written up.
//
// The two words a feed uses to say it has no classification are said rather
// than drawn as one. "NVD-CWE-OTHER" beside a name reads as a category
// somebody put the flaw in, and nobody did.
export function Weaknesses({ of }: { of: string[] }) {
  if (of.length === 0) return null;
  const said = of.filter((each) => !unclassified(each));
  if (said.length === 0) {
    return <p className="hint">Nothing classifies this kind of flaw.</p>;
  }
  return (
    <ul className="refs" style={{ margin: "8px 0 0" }}>
      {said.map((id) => {
        const name = nameOf(id);
        const at = readAbout(id);
        return (
          <li key={id}>
            {at ? (
              <Outward href={at} className="id">
                {id}
              </Outward>
            ) : (
              <span className="id">{id}</span>
            )}
            {name && <span className="hint">{name}</span>}
          </li>
        );
      })}
    </ul>
  );
}
