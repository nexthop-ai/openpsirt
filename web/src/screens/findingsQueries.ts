// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { bumpQuery } from "./FindingsViews";
import { acrossProducts, findingsPageKey, type withinVariant } from "./list";

// The findings list's reads: the rows of the view by issue, and each view's
// own count.
//
// `spanning` is the list across every product the reader may see, which has
// no view by component or by upgrade. `selection` is the branch and variant
// the list is narrowed to, beside the filters in `query`.
export function useFindingsViews({
  product,
  stream,
  variant,
  spanning,
  query,
  selection,
  view,
}: {
  product: string;
  stream: string;
  variant: string;
  spanning: boolean;
  query: ReturnType<typeof withinVariant>;
  selection: { stream?: string; variant?: string };
  view: string;
}) {
  const findings = useQuery({
    queryKey: findingsPageKey(product, stream, variant, query),
    queryFn: async () =>
      unwrap(
        spanning
          ? await api.GET("/v1/findings", { params: { query: acrossProducts(query) } })
          : await api.GET("/v1/products/{product}/findings", {
              params: { path: { product }, query: { ...query, ...selection } },
            }),
      ),
    enabled: view === "issues",
    // The rows on screen stay there while the next answer is read, so changing
    // one filter keeps the search box, the chips, the count and the controls
    // drawn and the cursor where it was.
    placeholderData: keepPreviousData,
  });

  // Each view's own count, on the button that switches to it.
  //
  // The three answer the same narrowing at three grains, and the difference
  // between them is the whole reason to switch: a product whose by-issue list
  // is 7,455 rows is 341 by component and 284 by upgrade. Without the counts
  // the list opens on its longest view and reads as the only one.
  //
  // The by-component and by-upgrade counts are asked with a limit of zero,
  // which answers the total without reading a page or what decorates it. The
  // by-issue count is the one the screen already holds where the by-issue view
  // is what is drawn, so it is asked only from the other two, with a page of
  // one: the findings list has no count-only answer.
  const byIssue = useQuery({
    queryKey: ["findings", "count", product, stream, variant, query],
    enabled: view !== "issues",
    queryFn: async () =>
      unwrap(
        spanning
          ? await api.GET("/v1/findings", {
              params: { query: { ...acrossProducts(query), limit: 1, offset: 0 } },
            })
          : await api.GET("/v1/products/{product}/findings", {
              params: {
                path: { product },
                query: { ...query, ...selection, limit: 1, offset: 0 },
              },
            }),
      ),
  });
  const byComponent = useQuery({
    queryKey: ["findings-by-component", "count", product, selection, query],
    enabled: !spanning,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings/components", {
          params: {
            path: { product },
            query: {
              ...(query as unknown as Record<string, never>),
              ...selection,
              limit: 0,
              offset: 0,
            },
          },
        }),
      ),
  });
  const byUpgrade = useQuery({
    queryKey: ["fix-bundles", "count", product, selection, query],
    enabled: !spanning,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/fix-bundles", {
          params: {
            path: { product },
            query: bumpQuery({ product, ...selection }, query, 0, 0) as Record<string, never>,
          },
        }),
      ),
  });

  return { findings, byIssue, byComponent, byUpgrade };
}
