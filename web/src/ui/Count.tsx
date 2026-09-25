// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import { Refused } from "../api/queries";

// What a count is read from: one query, or several a figure sums.
export type Readable = { isPending: boolean; isError: boolean; error: unknown };

const all = (of: Readable | Readable[]) => (Array.isArray(of) ? of : [of]);

// Whether every read a figure depends on has answered. An empty state is
// drawn only then: "nothing waiting" over a read still in flight is a zero
// said before it is known.
export function known(of: Readable | Readable[]): boolean {
  return all(of).every((each) => !each.isPending && !each.isError);
}

// A count in one of three states. Waiting, it is a faint placeholder and
// never a digit, because a zero drawn while the read is in flight is a
// confident answer to a question not yet asked. Failed, it is a dash with the
// server's reason on hover. Answered, it is the figure.
export function Count({ of, children }: { of: Readable | Readable[]; children: () => ReactNode }) {
  const reads = all(of);
  const failed = reads.find((each) => each.isError);
  if (failed) {
    const said = failed.error instanceof Refused ? failed.error.message : "Could not be read";
    return (
      <span className="count-failed" title={said}>
        —
      </span>
    );
  }
  if (reads.some((each) => each.isPending)) {
    return <span className="count-pending" aria-busy="true" aria-label="Loading" />;
  }
  return <>{children()}</>;
}
