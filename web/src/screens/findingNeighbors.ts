// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { findingsPageKey, fromAt, listQuery, where, windowFor, withinVariant } from "./list";
import { findingAt } from "../app/routes";
import type { components } from "../api/schema";

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
  // By what the row is rather than by where it sat: a row may have moved or
  // gone since it was drawn.
  const indexIn = useMemo(
    () => (items: Item[]) =>
      items.findIndex(
        (row) =>
          row.vulnerability === vulnerability &&
          row.component === component &&
          (row.version ?? "") === version &&
          (!ecosystem || (row.ecosystem ?? "") === ecosystem) &&
          (!namespace || (row.namespace ?? "") === namespace),
      ),
    [vulnerability, component, version, ecosystem, namespace],
  );
  // The page the list itself holds under the same address, where the reader
  // came from it: the findings list caches its rows under this key. Where the
  // finding sits inside that page with a row on either side — or at an end of
  // the whole list — the neighbors are already known and nothing is asked.
  const client = useQueryClient();
  const held = useMemo(() => {
    if (!walking) return undefined;
    const page = client.getQueryData<Page>(
      findingsPageKey(product, list.get("stream") ?? "", list.get("variant") ?? "", listed),
    );
    if (!page) return undefined;
    const items = page.items ?? [];
    const i = indexIn(items);
    // At the largest page the window is the page itself, so asking for it
    // would read the same rows again: the walk ends at the page's edge.
    const wide = windowFor(listed.offset, listed.limit);
    const widens = wide.offset !== listed.offset || wide.limit !== listed.limit;
    const first = widens && i === 0 && listed.offset > 0;
    const last = widens && i === items.length - 1 && listed.offset + items.length < page.total;
    return i < 0 || first || last ? undefined : page;
  }, [client, walking, product, list, listed, indexIn]);
  // Otherwise the page is asked for widened by one at each end, so that
  // stepping off a page finds the row on the next one rather than stopping at
  // a boundary the reader never chose.
  const span = useMemo(
    () =>
      held
        ? { offset: listed.offset, limit: listed.limit }
        : windowFor(listed.offset, listed.limit),
    [held, listed],
  );
  const asked = useQuery({
    enabled: walking && !held,
    queryKey: ["walk", product, from],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings", {
          params: { path: { product }, query: { ...listed, ...span, ...where(list) } },
        }),
      ),
  });
  const neighbors = held ?? asked.data;
  return useMemo(() => {
    const items = neighbors?.items ?? [];
    const i = indexIn(items);
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
      total: neighbors?.total ?? 0,
      previous: step(i - 1),
      next: step(i + 1),
    };
  }, [neighbors, indexIn, span, listed.limit, list, from, rule, product]);
}

// A page of the findings list, as the client types it.
type Page = { items: Item[] | null; total: number };
type Item = components["schemas"]["FindingBody"];
