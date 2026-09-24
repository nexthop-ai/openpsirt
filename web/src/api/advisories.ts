// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";

// An advisory as the screens read and change it: the list, the one, what it
// covers, and what has gone out.
//
// One module, because every act here moves more than one of those reads. A
// flaw named on an advisory opens an edition, which takes back every
// agreement standing and changes the status — so a screen invalidating only
// what it called would leave the agreement panel saying an agreement stands
// against a document nobody has read.

export type Listed = Body<"AdvisoryListedBody">;
export type Advisory = Body<"AdvisoryBody">;
export type Covered = Body<"CoveredBody">;
export type Issuance = Body<"IssuanceBody">;

// Everything an act against an advisory can move.
//
// One list, shared by every mutation below, for the reason the claim's own
// list says: two copies drift, and the half that gets forgotten is the one
// that reports a control as still holding after the act that took it away.
//
// `advisories` covers the list screen and the panel on a flaw that asks what
// already covers it — both are keyed under that name, and a key is matched by
// its prefix.
export function useAfterAdvisory() {
  const queries = useQueryClient();
  return () => {
    void queries.invalidateQueries({ queryKey: ["advisories"] });
    void queries.invalidateQueries({ queryKey: ["advisory"] });
    void queries.invalidateQueries({ queryKey: ["advisory-document"] });
    void queries.invalidateQueries({ queryKey: ["advisory-issuances"] });
  };
}

// The rows one request carries. The server's own default, named here so the
// pager and the request cannot disagree about where a page ends.
export const PAGE = 50;

export function useAdvisories(offset: number): UseQueryResult<{
  items: Listed[] | null;
  total?: number;
}> {
  return useQuery({
    queryKey: ["advisories", offset],
    queryFn: async () =>
      unwrap(await api.GET("/v1/advisories", { params: { query: { limit: PAGE, offset } } })),
  });
}

export function useAdvisory(advisory: string): UseQueryResult<Advisory> {
  return useQuery({
    queryKey: ["advisory", advisory],
    queryFn: async () =>
      unwrap(await api.GET("/v1/advisories/{advisory}", { params: { path: { advisory } } })),
  });
}

// The CSAF document this advisory generates.
//
// Asked only where the advisory covers something. One covering nothing is
// refused — the standard requires at least one vulnerability — and a refusal
// every visit is a failure drawn on a screen where nothing has failed.
export function useAdvisoryDocument(advisory: string, covers: number) {
  return useQuery({
    enabled: covers > 0,
    queryKey: ["advisory-document", advisory],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/advisories/{advisory}/document", { params: { path: { advisory } } }),
      ),
    retry: false,
  });
}

export function useIssuances(advisory: string): UseQueryResult<{ items: Issuance[] | null }> {
  return useQuery({
    queryKey: ["advisory-issuances", advisory],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/advisories/{advisory}/issuance", { params: { path: { advisory } } }),
      ),
  });
}

// Renaming an advisory. What it is called is a decision somebody makes about a
// document, so it is its own act rather than part of starting one.
export function useRetitle() {
  const done = useAfterAdvisory();
  return useMutation({
    mutationFn: async ({ advisory, title }: { advisory: string; title: string }) =>
      unwrap(
        await api.PATCH("/v1/advisories/{advisory}", {
          params: { path: { advisory } },
          body: { title },
        }),
      ),
    onSuccess: done,
  });
}

export function useNameAFlaw() {
  const done = useAfterAdvisory();
  return useMutation({
    mutationFn: async ({
      advisory,
      product,
      vulnerability,
    }: {
      advisory: string;
      product: string;
      vulnerability: string;
    }) =>
      unwrap(
        await api.POST("/v1/advisories/{advisory}/issues", {
          params: { path: { advisory } },
          body: { product, vulnerability },
        }),
      ),
    onSuccess: done,
  });
}

export function useTakeAFlawOff() {
  const done = useAfterAdvisory();
  return useMutation({
    mutationFn: async ({
      advisory,
      product,
      vulnerability,
    }: {
      advisory: string;
      product: string;
      vulnerability: string;
    }) =>
      unwrap(
        await api.DELETE("/v1/advisories/{advisory}/issues/{product}/{vulnerability}", {
          params: { path: { advisory, product, vulnerability } },
        }),
      ),
    onSuccess: done,
  });
}

// Agreeing to what an advisory says now.
//
// Offered to everybody who reaches the screen. Who may agree is the store's
// rule — neither the person who started it nor the author of the edition
// standing — and it is enforced there against the record rather than here
// against what a page happens to know, which is a count and not a name.
export function useAgree() {
  const done = useAfterAdvisory();
  return useMutation({
    mutationFn: async ({ advisory }: { advisory: string }) =>
      unwrap(
        await api.POST("/v1/advisories/{advisory}/approval", { params: { path: { advisory } } }),
      ),
    onSuccess: done,
  });
}

// Taking back every agreement standing on what it says now, not only your own.
export function useTakeAgreementBack() {
  const done = useAfterAdvisory();
  return useMutation({
    mutationFn: async ({ advisory }: { advisory: string }) =>
      unwrap(
        await api.DELETE("/v1/advisories/{advisory}/approval", { params: { path: { advisory } } }),
      ),
    onSuccess: done,
  });
}

export function useRecordIssued() {
  const done = useAfterAdvisory();
  return useMutation({
    mutationFn: async ({ advisory, summary }: { advisory: string; summary: string }) =>
      unwrap(
        await api.POST("/v1/advisories/{advisory}/issuance", {
          params: { path: { advisory } },
          body: { ...(summary ? { summary } : {}) },
        }),
      ),
    onSuccess: done,
  });
}
