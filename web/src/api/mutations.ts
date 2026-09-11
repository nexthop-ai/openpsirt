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
