// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap, whichOf } from "../api/queries";
import { useInvalidating } from "../api/invalidate";
import { handedBack } from "../api/intake";
import type { Row, withinVariant } from "./list";

// The most rows one assignment may name. The server takes this many picked rows
// in one request; past it, "select all" asks by the filter and names none.
export const NAMED_AT_ONCE = 2000;

// The reads a decision on the findings list makes stale. The view counts are
// held for five minutes and not all sit under the `findings` prefix, so each
// is named.
export const listReads = ["findings", "findings-by-component", "planned-upgrades", "holdings"];

// useHandOver is the two ways the findings list hands rows to a person or a
// team.
//
// `hand` assigns one row at the build `buildOf` names for it. Nothing is
// invalidated per row: handing over a selection is a loop of these, and
// invalidating on each one interleaves a list refetch between every write. The
// loop calls `handed` once when it is done.
//
// `handMatching` hands a selection over in one request, where the list is one
// product's. The server resolves the rows from the same filter the list is
// read with, so "every row matching" is what the count above says rather than
// what one page held; picked rows travel as `only`.
//
// `handed` reads again what a hand-over moves: the list's own reads, and every
// list of who holds what, which a hand-back moves the same way.
export function useHandOver({
  product,
  query,
  selection,
  buildOf,
}: {
  product: string;
  query: ReturnType<typeof withinVariant>;
  selection: { branch_or_tag?: string; variant?: string };
  buildOf: (row: Row) => { product: string; branch_or_tag: string; variant: string };
}) {
  const hand = useMutation({
    mutationFn: async (to: { row: Row; who: string; team: boolean }) =>
      unwrap(
        await api.PUT(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/findings/{issue}/components/{component}/assignment",
          {
            params: {
              path: {
                ...buildOf(to.row),
                issue: to.row.vulnerability ?? "",
                component: to.row.component ?? "",
              },
              query: whichOf(to.row),
            },
            body: to.team ? { team: to.who } : { person: to.who },
          },
        ),
      ),
  });

  const handMatching = useMutation({
    mutationFn: async (to: { who: string; team: boolean; only?: Row[] }) =>
      unwrap(
        await api.POST("/v1/products/{product}/findings/assignment", {
          params: {
            path: { product },
            query: Object.fromEntries(
              Object.entries({ ...query, ...selection }).filter(
                ([key]) => key !== "limit" && key !== "offset",
              ),
            ) as Record<string, never>,
          },
          body: {
            ...(to.team ? { team: to.who } : { person: to.who }),
            ...(to.only
              ? {
                  only: to.only.map((row) => ({
                    vulnerability: row.vulnerability ?? "",
                    fold: row.fold ?? "",
                  })),
                }
              : {}),
          },
        }),
      ),
  });

  const handed = useInvalidating([...new Set([...listReads, ...handedBack])]);

  return { hand, handMatching, handed };
}
