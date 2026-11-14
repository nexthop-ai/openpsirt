// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQueryClient } from "@tanstack/react-query";

// useInvalidating is the act of reading a set of keys again, each matched by
// its prefix. Every set an act moves is a list handed to this, so how a set is
// applied is written once.
export function useInvalidating(keys: readonly string[]): () => void {
  const queries = useQueryClient();
  return () => {
    for (const key of keys) void queries.invalidateQueries({ queryKey: [key] });
  };
}
