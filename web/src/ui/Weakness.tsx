// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Outward } from "./Outward";
import { called, readAbout, unclassified, type Named } from "./cwe";

// The kind of flaw, as a reader can use it.
//
// Every identifier is shown, named, and linked to where it is written up.
// "CWE-401" as a bare number is not something anybody knows. The name is the
// short one where the weakness is common and the catalog's otherwise, whole,
// with the catalog's on hover.
//
// The two words a feed uses to say it has no classification are said rather
// than drawn as one. "NVD-CWE-OTHER" beside a name reads as a category
// somebody put the flaw in, and nobody did.
export function Weaknesses({ of }: { of: Named[] }) {
  if (of.length === 0) return null;
  const said = of.filter((each) => !unclassified(each.id));
  if (said.length === 0) {
    return <p className="hint">Nothing classifies this kind of flaw.</p>;
  }
  return (
    <ul className="refs" style={{ margin: "8px 0 0" }}>
      {said.map((each) => {
        const name = called(each);
        const at = readAbout(each.id);
        return (
          <li key={each.id}>
            {at ? (
              <Outward href={at} className="id">
                {each.id}
              </Outward>
            ) : (
              <span className="id">{each.id}</span>
            )}
            {name && (
              <span className="hint" title={each.name}>
                {name}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
