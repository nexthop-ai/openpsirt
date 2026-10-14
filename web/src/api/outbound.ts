// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import { unwrap } from "./queries";

// Every destination a notification leaves by, webhooks and chat channels
// alike: one read under one key, which the two screens filter by platform.
export function useDestinations() {
  return useQuery({
    queryKey: ["outbound"],
    queryFn: async () => unwrap(await api.GET("/v1/outbound", {})),
  });
}

// Retiring one destination, by its name and the kind it takes.
export function useRetireDestination() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async (where: { name: string; kind: string }) =>
      unwrap(await api.DELETE("/v1/outbound/{name}/{kind}", { params: { path: where } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["outbound"] }),
  });
}
