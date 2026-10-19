// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";

// The upstream a product trusts, what it offers for review, and declining one
// of its statements.
//
// One definition of each read, so an invalidation after an act reaches every
// screen showing what the act changed.

export type Upstream = Body<"UpstreamBody">;

// The upstream a product trusts, or null where it trusts none.
export function useUpstream(product: string, enabled = true) {
  return useQuery({
    queryKey: ["upstream", product],
    enabled: enabled && product !== "",
    queryFn: async () => {
      const answer = await api.GET("/v1/products/{product}/upstream", {
        params: { path: { product } },
      });
      if (answer.response.status === 404) return null;
      return unwrap(answer);
    },
  });
}

// Reading an upstream's description, for an administrator to confirm.
export function useInspect(product: string) {
  return useMutation({
    mutationFn: async (url: string) =>
      unwrap(
        await api.POST("/v1/products/{product}/upstream/inspection", {
          params: { path: { product } },
          body: { url },
        }),
      ),
  });
}

// Trusting an upstream, or its key again, and stopping trusting it.
export function useTrust(product: string) {
  const queries = useQueryClient();
  const settled = () => {
    void queries.invalidateQueries({ queryKey: ["upstream", product] });
    void queries.invalidateQueries({ queryKey: ["upstream-offers"] });
  };
  const trust = useMutation({
    mutationFn: async (body: { url: string; fingerprint?: string }) =>
      unwrap(
        await api.PUT("/v1/products/{product}/upstream", {
          params: { path: { product } },
          body,
        }),
      ),
    onSuccess: settled,
  });
  const withdraw = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.DELETE("/v1/products/{product}/upstream", { params: { path: { product } } }),
      ),
    onSuccess: settled,
  });
  return { trust, withdraw };
}

// What upstreams offer for review, in one product or every product the reader
// sees.
export function useOffers(product = "") {
  return useQuery({
    queryKey: ["upstream-offers", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/upstream-offers", {
          params: { query: product ? { product } : {} },
        }),
      ),
  });
}

// What a product's upstream says about a component of one name.
export function useUpstreamSaid(product: string, component: string) {
  return useQuery({
    queryKey: ["upstream-said", product, component],
    enabled: product !== "" && component !== "",
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/components/{component}/upstream-statements", {
          params: { path: { product, component } },
        }),
      ),
  });
}

// Declining one of an upstream's statements, or taking that back. Either
// changes what closes findings, so every read of findings and statements is
// asked again.
export function useDecline() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async ({ statement, declined }: { statement: number; declined: boolean }) => {
      const params = { params: { path: { statement } } };
      return unwrap(
        declined
          ? await api.PUT("/v1/statements/{statement}/declined", params)
          : await api.DELETE("/v1/statements/{statement}/declined", params),
      );
    },
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["upstream-offers"] });
      void queries.invalidateQueries({ queryKey: ["upstream-said"] });
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });
}
