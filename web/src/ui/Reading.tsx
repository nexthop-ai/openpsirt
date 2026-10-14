// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import { Failed } from "./Failed";
import { Loading } from "./Loading";

// A read as the arms below need it: a query result, or anything shaped like one.
type Read<T> = { isPending: boolean; isError: boolean; error: unknown; data: T | undefined };

// What a read draws, in one of three arms. Waiting, the loading line. Failed,
// what the server said under `what`. Answered, whatever `children` draws from
// the data, an empty state included. The failure arm is not optional, so a
// screen drawn through this cannot show "none" for a read that never answered.
export function Reading<T>({
  query,
  what,
  inline = false,
  children,
}: {
  query: Read<T>;
  what: string;
  inline?: boolean;
  children: (data: T) => ReactNode;
}) {
  if (query.isError) return <Failed error={query.error} what={what} />;
  if (query.isPending || query.data === undefined) return <Loading inline={inline} />;
  return <>{children(query.data)}</>;
}

// The failure of a read whose answer is drawn elsewhere, such as the options of
// a picker, which stay usable while the sentence says the list is incomplete.
// Nothing while the read is waiting or answered.
export function Unread({ of, what }: { of: { isError: boolean; error: unknown }; what: string }) {
  return of.isError ? <Failed error={of.error} what={what} /> : null;
}
