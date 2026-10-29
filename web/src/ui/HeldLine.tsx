// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import { counted, heldLine, type Holding } from "../app/families";

// The line standing in for a family's counts where the reader does not read
// them at the screen's scope, or beside them where one half is read alone.
//
// A screen counting the family beside other things says nothing to a reader
// holding it in no product, because nothing of the family is drawn there. A
// screen whose subject is the family (`whole`) says it to them too, since the
// line is all it has to draw.
export function HeldLine({ at, whole = false }: { at: Holding; whole?: boolean }) {
  const line = heldLine(at);
  if (!line || (!whole && at.held === "nowhere")) return null;
  return <p className="hint">{line}</p>;
}

// One row's count of a family, in a table spanning products. A product read
// for something else carries a dash with the line on hover, because a zero
// there reads as nothing open; one read in half says so on hover.
export function HeldCell({ at, children }: { at: Holding; children: ReactNode }) {
  if (!counted(at)) {
    return (
      <td className="num hint" title={heldLine(at)}>
        —
      </td>
    );
  }
  return (
    <td className="num" title={heldLine(at) || undefined}>
      {children}
    </td>
  );
}
