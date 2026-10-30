// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { counted, holding, type Holding } from "./families";
import type { Who } from "./session";

// The families of work somebody holds.
export type WorkFamily = "dependency" | "code";

// What one family of the reader's own work says at a scope.
//
// Asked whatever the reader reads: work handed to somebody stays theirs to
// see where it is disclosed, so a reader of nothing can still hold some. The
// count is drawn where it counts what it says, or where it is above zero,
// since a held row is theirs; elsewhere the holding's line stands in.
function ownWorkDrawn(at: Holding, total: number | undefined): boolean {
  return counted(at) || (total ?? 0) > 0;
}

// One family of what the reader holds, one page of it.
export function useOwnWork(
  who: Who | null | undefined,
  family: WorkFamily,
  scope: Record<string, string>,
  page: { limit: number; offset: number },
) {
  const at = holding(who, family, scope.product);
  const query = useQuery({
    queryKey: ["assigned", "me", family, scope, page.limit, page.offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/people/{identity}/assignments", {
          params: {
            path: { identity: "me" },
            query: { family, limit: page.limit, offset: page.offset, ...scope },
          },
        }),
      ),
  });
  return { family, at, query, drawn: ownWorkDrawn(at, query.data?.total) };
}
