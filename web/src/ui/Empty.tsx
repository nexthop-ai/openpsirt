// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";

// The sentence a list shows when it has nothing in it. A blank panel reads as
// broken,
// and "no results" reads as a filter problem even when nothing was filtered —
// so the caller says which of the two this is.
//
// An emptiness the reader caused carries the way to undo it, which belongs
// here: a narrowed list that matches nothing is a dead end otherwise, with the
// controls that produced it scrolled off above.
export function Empty({
  title,
  detail,
  children,
}: {
  title: string;
  detail?: string;
  children?: ReactNode;
}) {
  return (
    <div className="card" style={{ textAlign: "center", padding: "34px 20px" }}>
      <p style={{ margin: 0, fontWeight: 600 }}>{title}</p>
      {detail && (
        <p className="hint" style={{ margin: "4px 0 0" }}>
          {detail}
        </p>
      )}
      {children && <p style={{ margin: "14px 0 0" }}>{children}</p>}
    </div>
  );
}
