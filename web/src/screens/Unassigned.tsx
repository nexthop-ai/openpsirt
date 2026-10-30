// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link, Navigate } from "react-router-dom";
import type { Who } from "../app/session";
import { heldLine } from "../app/families";
import { Count } from "../ui/Count";
import { ROUTES } from "../app/routes";
import { unownedAt, useUnowned, type Unowned } from "./unowned";

// Work nobody holds, for a reader counting both families: one card per
// family, each with its own count, opening its own list. The two lists stay
// apart because an unjudged code result must never reach a published
// statement, and a rule at a place and an advisory at a component are
// different units.
//
// A reader counting one family is taken straight to its list, so the address
// a bookmark or an old digest carries still lands on work.
export function Unassigned({ who }: { who: Who }) {
  const unowned = useUnowned(who);
  const opens = unownedAt(unowned);
  if (opens.to !== ROUTES.unassigned) return <Navigate to={opens.to} replace />;
  return (
    <>
      <div className="screen-head">
        <h2>Unassigned</h2>
        <p>Work nobody holds, across every product you read</p>
      </div>
      <div className="panels">
        <Door
          title="Dependency findings"
          detail="What a scan of an inventory matched, and the flaws recorded beside them, that nobody holds and nobody has decided."
          unowned={unowned.dependency}
        />
        <Door
          title="Code findings"
          detail="What security testing reported that nobody holds."
          unowned={unowned.code}
        />
      </div>
    </>
  );
}

function Door({ title, detail, unowned }: { title: string; detail: string; unowned: Unowned }) {
  const line = heldLine(unowned.at);
  return (
    <div className="panel">
      <header>
        <h3>{title}</h3>
        <span className="tally">
          <Count of={unowned.count}>
            {() => (unowned.count.data?.total ?? 0).toLocaleString()}
          </Count>
        </span>
      </header>
      <p className="reading">{detail}</p>
      {line && <p className="hint">{line}</p>}
      <footer>
        <Link to={unowned.to} className="linkish">
          Open the list →
        </Link>
      </footer>
    </div>
  );
}
