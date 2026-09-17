import { keepPreviousData, useQuery, type UseQueryResult } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";

// The catalog cascade: products, then a product's branches and tags, then what
// it is built as.
//
// One definition, because two are one cache. The scope picker and the upload
// panel each held their own copy of these three reads, including the query
// keys — so the two already shared cache entries while being enabled under
// different conditions, and neither said so. A fourth level, a bound on the
// product list, or an invalidation after a product is declared would have
// landed in one of them.

export type Product = Body<"ProductBody">;
export type Stream = Body<"StreamBody">;
export type Variant = Body<"VariantBody">;

// The three, as one hook. The variants are the product's own — what it is
// built as, rather than what one release was — and are read whenever a product
// is chosen, because a picker offers them the moment the branch goes back to
// "all" and a read that waits for that is a wait in front of a choice.
//
// **None of these asks for the counts.** What is open against a row is the
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
  const products = useQuery({
    queryKey: ["products"],
    enabled: open,
    placeholderData: keepPreviousData,
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });
  const streams = useQuery({
    queryKey: ["streams", product],
    enabled: open && !!product,
    placeholderData: keepPreviousData,
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/streams", { params: { path: { product } } })),
  });
  const variants = useQuery({
    queryKey: ["variants", product],
    enabled: open && !!product,
    placeholderData: keepPreviousData,
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/variants", { params: { path: { product } } })),
  });
  return { products, streams, variants };
}

// What one release was built as, which is a different question from what the
// product is built as — and a different route. Only the scope picker asks it,
// once a branch or tag is chosen.
//
// **The list it replaces stays on screen while this is read.** Picking a branch
// switches the variant column from the product's list to this one, and the two
// are different cache entries — so the column emptied and refilled on every
// branch chosen, which reads as the picker losing what it had rather than as
// it answering a narrower question. They are usually the same names.
export function useReleaseVariants(
  open: boolean,
  product: string,
  stream: string,
): UseQueryResult<{ items: Variant[] | null }> {
  return useQuery({
    queryKey: ["variants", product, stream],
    enabled: open && !!product && !!stream,
    placeholderData: keepPreviousData,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants", {
          params: { path: { product, stream } },
        }),
      ),
  });
}
