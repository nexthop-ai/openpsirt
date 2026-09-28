// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap, whichOf } from "../api/queries";
import type { Row, withinVariant } from "./list";

// useHandOver is the two ways the findings list hands rows to a person or a
// team.
//
// `hand` assigns one row at the build `buildOf` names for it. Nothing is
// invalidated per row: handing over a selection is a loop of these, and
// invalidating on each one interleaves a list refetch between every write. The
// loop invalidates once when it is done.
//
// `handMatching` hands a selection over in one request, where the list is one
// product's. The server resolves the rows from the same filter the list is
// read with, so "every row matching" is what the count above says rather than
// what one page held; picked rows travel as `only`.
export function useHandOver({
  product,
  query,
  selection,
  buildOf,
}: {
  product: string;
  query: ReturnType<typeof withinVariant>;
  selection: { stream?: string; variant?: string };
  buildOf: (row: Row) => { product: string; stream: string; variant: string };
}) {
  const hand = useMutation({
    mutationFn: async (to: { row: Row; who: string; team: boolean }) =>
      unwrap(
        await api.PUT(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/assignment",
          {
            params: {
              path: {
                ...buildOf(to.row),
                vulnerability: to.row.vulnerability ?? "",
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

  return { hand, handMatching };
}
