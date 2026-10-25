// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";
import { useAfterClaim } from "./claims";
import type { Build } from "../app/routes";

// Static analysis leads: the queue, one lead's evidence, and the product's
// standing rules and important paths that decide what reaches the queue.
//
// One module, because every act here moves more than one read: a judgment
// about a lead moves the queue, the lead, the leads it is one flaw with and
// the review queue, and a standing rule moves every lead it covers.

export type Lead = Body<"LeadRowBody">;
export type Leads = Body<"LeadsOutputBody">;
export type Evidence = Body<"LeadEvidenceBody">;
export type LeadState = Evidence["state"];
export type LeadPlace = Body<"LeadPlace">;
export type LeadOutcome = Body<"LeadDecisionBody">["outcome"];
export type LeadReason = NonNullable<Body<"LeadDecisionBody">["reason"]>;
export type LeadRule = Body<"LeadRuleBody">;
export type LeadRuleState = LeadRule["state"];

// The rows one request carries, named so the pager and the request agree.
export const PAGE = 50;

// Everything an act on a lead or a rule can move.
function useAfterLead() {
  const queries = useQueryClient();
  const claimed = useAfterClaim();
  // The claim's own set carries the leads and the lead; a standing rule's
  // coverage moves with either.
  return () => {
    void queries.invalidateQueries({ queryKey: ["lead-rules"] });
    claimed();
  };
}

export function useLeads(
  product: string,
  asked: { stream?: string; variant?: string; state?: LeadState; offset?: number },
): UseQueryResult<Leads> {
  return useQuery({
    queryKey: ["leads", product, asked],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/leads", {
          params: {
            path: { product },
            query: {
              limit: PAGE,
              offset: asked.offset ?? 0,
              ...(asked.stream ? { stream: asked.stream } : {}),
              ...(asked.variant ? { variant: asked.variant } : {}),
              ...(asked.state ? { state: asked.state } : {}),
            },
          },
        }),
      ),
  });
}

export function useLead(build: Build, place: string): UseQueryResult<Evidence> {
  return useQuery({
    queryKey: ["lead", build.product, build.stream, build.variant, place],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}", {
          params: { path: { ...build, place } },
        }),
      ),
    retry: false,
  });
}

export function useDecideLead(build: Build, place: string) {
  const after = useAfterLead();
  return useMutation({
    mutationFn: async (body: Body<"LeadDecisionBody">) =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/decision",
          { params: { path: { ...build, place } }, body },
        ),
      ),
    onSuccess: after,
  });
}

export function useFixLead(build: Build, place: string) {
  const after = useAfterLead();
  return useMutation({
    mutationFn: async (because: string) =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/fixed",
          { params: { path: { ...build, place } }, body: { because } },
        ),
      ),
    onSuccess: after,
  });
}

export function useEscalateLead(product: string, place: string) {
  const after = useAfterLead();
  return useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/leads/{place}/escalation", {
          params: { path: { product, place } },
        }),
      ),
    onSuccess: after,
  });
}

export function useLeadRules(product: string): UseQueryResult<LeadRule[]> {
  return useQuery({
    queryKey: ["lead-rules", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/lead-rules", { params: { path: { product } } }))
        .items ?? [],
  });
}

export function useProposeLeadRule(product: string) {
  const after = useAfterLead();
  return useMutation({
    mutationFn: async (body: Body<"Propose-lead-ruleRequest">) =>
      unwrap(
        await api.POST("/v1/products/{product}/lead-rules", {
          params: { path: { product } },
          body,
        }),
      ),
    onSuccess: after,
  });
}

export function useApproveLeadRule(product: string) {
  const after = useAfterLead();
  return useMutation({
    mutationFn: async (id: number) =>
      unwrap(
        await api.POST("/v1/products/{product}/lead-rules/{id}/approval", {
          params: { path: { product, id } },
        }),
      ),
    onSuccess: after,
  });
}

export function useRetireLeadRule(product: string) {
  const after = useAfterLead();
  return useMutation({
    mutationFn: async (id: number) =>
      unwrap(
        await api.DELETE("/v1/products/{product}/lead-rules/{id}", {
          params: { path: { product, id } },
        }),
      ),
    onSuccess: after,
  });
}

export function useImportantPaths(product: string): UseQueryResult<string[]> {
  return useQuery({
    queryKey: ["important-paths", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/important-paths", {
          params: { path: { product } },
        }),
      ).paths ?? [],
  });
}

export function useSetImportantPaths(product: string) {
  const queries = useQueryClient();
  const after = useAfterLead();
  return useMutation({
    mutationFn: async (paths: string[]) =>
      unwrap(
        await api.PUT("/v1/products/{product}/important-paths", {
          params: { path: { product } },
          body: { paths },
        }),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["important-paths"] });
      after();
    },
  });
}
