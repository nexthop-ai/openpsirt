// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import type { Choice } from "../api/queries";

// pickedFrom is this page's address with one choice made, keeping the list it
// was opened from.
function pickedFrom(params: URLSearchParams, choice: Choice): string {
  const next = new URLSearchParams(params);
  for (const key of ["version", "ecosystem", "namespace"]) next.delete(key);
  next.set("version", choice.version);
  if (choice.ecosystem) next.set("ecosystem", choice.ecosystem);
  if (choice.namespace) next.set("namespace", choice.namespace);
  return next.toString();
}

// FindingWhich asks which of several components of one name the finding is
// about, where the build ships more than one and the address did not say.
export function FindingWhich({
  component,
  choices,
  params,
}: {
  component: string;
  choices: Choice[];
  params: URLSearchParams;
}) {
  return (
    <div className="card">
      <h3>Which {component}</h3>
      <p className="reading" style={{ marginBottom: 10 }}>
        This build ships more than one.
      </p>
      <ul className="refs">
        {choices.map((choice) => (
          <li key={`${choice.version} ${choice.ecosystem ?? ""} ${choice.namespace ?? ""}`}>
            <Link className="linkish id" to={`?${pickedFrom(params, choice)}`}>
              {choice.version}
            </Link>
            {choice.ecosystem && (
              <span className="hint">
                {choice.namespace ? `${choice.ecosystem}/${choice.namespace}` : choice.ecosystem}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
