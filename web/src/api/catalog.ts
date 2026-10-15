// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";

// The catalog cascade: products, then a product's branches and tags, then what
// it is built as.
//
// One definition of each read, because two definitions of one read are one
// cache entry under two sets of conditions, and an invalidation written
// against one key misses a read written under another. Every screen asking
// for these names asks through here.

export type Product = Body<"ProductBody">;
type Stream = Body<"StreamBody">;
type Variant = Body<"VariantBody">;

// The three, as one hook. The variants are the product's own — what it is
// built as, rather than what one release was — and are read whenever a product
// is chosen, because a picker offers them the moment the branch goes back to
// "all" and a read that waits for that is a wait in front of a choice.
//
// None of these asks for the counts. What is open against a row is the
// expensive half of a catalog read and every caller of this hook draws names:
// the scope picker and the upload panel between them were paying 0.39s a list
// for three numbers neither of them renders. The screens whose subject those
// numbers are ask for them, under keys of their own.
export function useCatalog(
  open: boolean,
  product = "",
): {
  products: UseQueryResult<{ items: Product[] | null }>;
  streams: UseQueryResult<{ items: Stream[] | null }>;
  variants: UseQueryResult<{ items: Variant[] | null }>;
} {
  const products = useProducts(open);
  const streams = useStreams(product, open);
  const variants = useProductVariants(product, open);
  return { products, streams, variants };
}

// The products, by name.
export function useProducts(enabled = true): UseQueryResult<{ items: Product[] | null }> {
  return useQuery({
    queryKey: ["products"],
    enabled,
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });
}

// One product's branches and tags, by name. Nothing is asked until a product
// is named.
export function useStreams(
  product: string,
  enabled = true,
): UseQueryResult<{ items: Stream[] | null }> {
  return useQuery({
    queryKey: ["streams", product],
    enabled: enabled && !!product,
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/streams", { params: { path: { product } } })),
  });
}

// One product's branches and tags, retired ones included. This resolves a
// name somebody arrived with rather than offering a choice, so a retired line
// is an answer here; it is keyed apart from the offered list because of it.
export function useStreamsResolving(product: string): UseQueryResult<{ items: Stream[] | null }> {
  return useQuery({
    queryKey: ["streams", product, "retired"],
    enabled: !!product,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams", {
          params: { path: { product }, query: { retired: true } },
        }),
      ),
  });
}

// What one product is built as, by name. Nothing is asked until a product is
// named.
export function useProductVariants(
  product: string,
  enabled = true,
): UseQueryResult<{ items: Variant[] | null }> {
  return useQuery({
    queryKey: ["variants", product],
    enabled: enabled && !!product,
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/variants", { params: { path: { product } } })),
  });
}

// The variants one release was built as, which is a different question from
// what the product is built as — and a different route. Asked once a branch or
// tag is chosen. Keyed under the product's variants, so declaring or renaming
// one reaches this read too.
//
// Nothing here holds a previous key's rows on screen. Three of these four
// are keyed on something the picker changes, so keeping the last answer would
// draw one product's branches under another product's name — and a variant
// picked from it reaches the server as a build that product has no such branch
// for, which is the selection this panel is not allowed to send. The variant
// column has a stand-in for the gap it leaves, and it is the product's own
// list, which is a superset of any one release's.
export function useReleaseVariants(
  open: boolean,
  product: string,
  stream: string,
): UseQueryResult<{ items: Variant[] | null }> {
  return useQuery({
    queryKey: ["variants", product, stream],
    enabled: open && !!product && !!stream,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants", {
          params: { path: { product, stream } },
        }),
      ),
  });
}
