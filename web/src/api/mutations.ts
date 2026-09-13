import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import { unwrap } from "./queries";
import { useAfterClaim } from "./claims";

export function useWithdraw() {
  const done = useAfterClaim();
  return useMutation({
    mutationFn: async ({ id }: { id: number }) =>
      unwrap(await api.DELETE("/v1/claims/{id}", { params: { path: { id } } })),
    onSuccess: done,
  });
}

export function useRevise() {
  const done = useAfterClaim();
  return useMutation({
    mutationFn: async ({ id, reasoning }: { id: number; reasoning: string }) =>
      unwrap(
        await api.PUT("/v1/claims/{id}/reasoning", {
          params: { path: { id } },
          body: { reasoning },
        }),
      ),
    onSuccess: done,
  });
}

// Replacing the text of a comment somebody already wrote.
//
// The new text overwrites the old rather than being kept as a revision: a
// comment is a remark, not a justification, and the two are kept differently
// on purpose. What the reader is told is only that it was edited.
export function useEditComment() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: number; body: string }) =>
      unwrap(
        await api.PUT("/v1/comments/{id}", {
          params: { path: { id } },
          body: { body },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["comments"] }),
  });
}

export function useComment() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: number; body: string }) =>
      unwrap(
        await api.POST("/v1/claims/{id}/comments", {
          params: { path: { id } },
          body: { body },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["comments"] }),
  });
}

// A note about an issue in a product, which records no judgment.
//
// Keyed on the issue and the product rather than on a claim, so it can be
// written before anybody has decided anything — which is the whole of what it
// is for. A row in the findings list is one issue at one source package and
// one issue is often several rows, so a note kept against a row would be
// written on one of them and hidden from the rest.
export function useNote() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async ({
      product,
      vulnerability,
      body,
    }: {
      product: string;
      vulnerability: string;
      body: string;
    }) =>
      unwrap(
        await api.POST("/v1/products/{product}/issues/{vulnerability}/notes", {
          params: { path: { product, vulnerability } },
          body: { body },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["notes"] }),
  });
}

// Replacing the text of a note somebody already wrote.
//
// What it said before is kept and read back behind the "edited" mark, the way
// a claim comment's is: a note goes public at disclosure with the rest of the
// record, and a record whose earlier text is unrecoverable is readable rather
// than checkable.
export function useEditNote() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: number; body: string }) =>
      unwrap(
        await api.PUT("/v1/notes/{id}", {
          params: { path: { id } },
          body: { body },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["notes"] }),
  });
}
