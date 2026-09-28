// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { fromAt, listQuery, where, windowFor, withinVariant } from "./list";
import { findingAt } from "../app/routes";

// useFindingNeighbors is where one finding sits in the list it was opened from,
// and the row before and after it.
//
// The list travels in the finding's address as one value, `from`. Present and
// empty is a list that asked for everything, which walks like any other;
// absent is no list at all, and then there is no order for this to be next
// in, so nothing is asked and the answer is nothing.
export function useFindingNeighbors(
  at: {
    product: string;
    vulnerability: string;
    component: string;
    version: string;
    ecosystem: string;
    namespace: string;
  },
  walking: boolean,
  from: string,
  // The saved filter the list was opened under, carried to each neighbor so
  // walking to the next finding does not quietly stop filling the form in.
  rule: string,
) {
  const { product, vulnerability, component, version, ecosystem, namespace } = at;
  const list = useMemo(() => new URLSearchParams(from), [from]);
  // Through the same guard the list applies: what is specific to a variant is
  // a question about one, and an address carrying the filter without a variant
  // is refused by the server — which would take the previous and next row with
  // it rather than the filter.
  const listed = useMemo(
    () => withinVariant(listQuery(list), Boolean(list.get("variant"))),
    [list],
  );
  // Widened by one at each end, so that stepping off a page finds the row on
  // the next one rather than stopping at a boundary the reader never chose.
  const span = useMemo(() => windowFor(listed.offset, listed.limit), [listed]);
  const neighbors = useQuery({
    enabled: walking,
    queryKey: ["walk", product, from],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings", {
          params: { path: { product }, query: { ...listed, ...span, ...where(list) } },
        }),
      ),
  });
  return useMemo(() => {
    const items = neighbors.data?.items ?? [];
    // By what the row is rather than by where it sat: the list is read afresh
    // here, and a row may have moved or gone since it was drawn.
    const i = items.findIndex(
      (row) =>
        row.vulnerability === vulnerability &&
        row.component === component &&
        (row.version ?? "") === version &&
        (!ecosystem || (row.ecosystem ?? "") === ecosystem) &&
        (!namespace || (row.namespace ?? "") === namespace),
    );
    if (i < 0) return null;
    function step(j: number) {
      const row = items[j];
      if (!row) return null;
      return {
        row,
        to: findingAt(
          {
            product,
            stream: row.stream || (list.get("stream") ?? ""),
            variant: row.variant || (list.get("variant") ?? ""),
          },
          row,
          // The neighbor is handed the list at the page it sits on, so a walk
          // that crosses a boundary leaves the list where the reader now is.
          fromAt(from, span.offset + j, listed.limit),
          rule,
        ),
      };
    }
    return {
      at: span.offset + i,
      total: neighbors.data?.total ?? 0,
      previous: step(i - 1),
      next: step(i + 1),
    };
  }, [
    neighbors.data,
    span,
    listed.limit,
    list,
    from,
    rule,
    product,
    vulnerability,
    component,
    version,
    ecosystem,
    namespace,
  ]);
}
