import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import { unwrap } from "./queries";

// Anything that changes a decision invalidates the same set: the queue it may
// have left, the decision itself, and the finding it hangs off. Listed once
// rather than per call, because the one somebody forgets is the screen that
// silently shows the old answer.
function useAfterDeciding() {
  const queries = useQueryClient();
  return () => {
    void queries.invalidateQueries({ queryKey: ["queue"] });
    void queries.invalidateQueries({ queryKey: ["decision"] });
    void queries.invalidateQueries({ queryKey: ["decided"] });
    void queries.invalidateQueries({ queryKey: ["home"] });
  };
}

export function useWithdraw() {
  const done = useAfterDeciding();
  return useMutation({
    mutationFn: async ({ id }: { id: number }) =>
      unwrap(await api.DELETE("/v1/claims/{id}", { params: { path: { id } } })),
    onSuccess: done,
  });
}

export function useRevise() {
  const done = useAfterDeciding();
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
