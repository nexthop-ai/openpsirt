// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, type Body } from "./client";
import type { paths } from "./schema";
import { unwrap } from "./queries";
import { useAfterDecision } from "./decisions";
import type { Build } from "../app/routes";

// Static analysis code findings: the queue, one code finding's evidence, and the product's
// suppression rules that dismiss code findings.
//
// One module, because every act here moves more than one read: a decision
// about a code finding moves the queue, the code finding, the code findings it is one flaw with and
// the review queue, and a suppression rule moves every code finding it covers.

export type CodeFinding = Body<"CodeFindingRowBody">;
export type CodeFindings = Body<"CodeFindingsOutputBody">;
export type Evidence = Body<"CodeFindingEvidenceBody">;
export type CodeFindingState = Evidence["state"];
export type CodeFindingOccurrence = Body<"CodeFindingOccurrence">;
export type CodeFindingOutcome = Body<"CodeFindingDecisionBody">["outcome"];
export type CodeFindingReason = NonNullable<Body<"CodeFindingDecisionBody">["reason"]>;
export type SuppressionRule = Body<"SuppressionRuleBody">;
export type SuppressionRuleState = SuppressionRule["state"];
export type CodeFindingMethod = NonNullable<
  NonNullable<paths["/v1/products/{product}/code-findings"]["get"]["parameters"]["query"]>["method"]
>;

// The rows one request carries, named so the pager and the request agree.
export const PAGE = 50;

// Everything an act on a code finding or a rule can move.
function useAfterCodeFinding() {
  const queries = useQueryClient();
  const decided = useAfterDecision();
  // The decision's own set carries the code findings and the code finding; a suppression rule's
  // coverage moves with either.
  return () => {
    void queries.invalidateQueries({ queryKey: ["suppression-rules"] });
    decided();
  };
}

// What narrows a product's code findings, on the list and in its file alike.
// `assigned` reads as the findings list's does: "nobody" keeps the code findings
// nobody holds.
type CodeFindingsAsked = {
  branch_or_tag?: string;
  variant?: string;
  series?: string;
  method?: CodeFindingMethod;
  state?: CodeFindingState;
  assigned?: "nobody";
};

// The narrowing as the query a request carries, with nothing for what is unset.
export function codeFindingsQuery(asked: CodeFindingsAsked): Record<string, string> {
  return Object.fromEntries(
    Object.entries(asked).filter((entry): entry is [string, string] => !!entry[1]),
  );
}

export function useCodeFindings(
  product: string,
  asked: CodeFindingsAsked & { offset?: number },
): UseQueryResult<CodeFindings> {
  return useQuery({
    queryKey: ["code-findings", product, asked],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/code-findings", {
          params: {
            path: { product },
            query: {
              limit: PAGE,
              offset: asked.offset ?? 0,
              ...(asked.branch_or_tag ? { branch_or_tag: asked.branch_or_tag } : {}),
              ...(asked.variant ? { variant: asked.variant } : {}),
              ...(asked.series ? { series: asked.series } : {}),
              ...(asked.method ? { method: asked.method } : {}),
              ...(asked.state ? { state: asked.state } : {}),
              ...(asked.assigned ? { assigned: asked.assigned } : {}),
            },
          },
        }),
      ),
  });
}

export type CodeFindingSeries = Body<"CodeFindingSeriesBody">;

// How many code findings each analyzer series of a product holds, by state. Keyed
// under the code findings, because every act that moves a code finding moves these.
export function useCodeFindingSeries(product: string): UseQueryResult<CodeFindingSeries[]> {
  return useQuery({
    enabled: product !== "",
    queryKey: ["code-findings", product, "by-series"],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/code-finding-series", {
          params: { path: { product } },
        }),
      ).items ?? [],
    retry: false,
  });
}

export function useCodeFinding(build: Build, occurrence: string): UseQueryResult<Evidence> {
  return useQuery({
    queryKey: ["code-finding", build.product, build.branch_or_tag, build.variant, occurrence],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}",
          {
            params: { path: { ...build, occurrence } },
          },
        ),
      ),
    retry: false,
  });
}

export function useDecideCodeFinding(build: Build, occurrence: string) {
  const after = useAfterCodeFinding();
  return useMutation({
    mutationFn: async (body: Body<"CodeFindingDecisionBody">) =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/decision",
          { params: { path: { ...build, occurrence } }, body },
        ),
      ),
    onSuccess: after,
  });
}

export function useFixCodeFinding(build: Build, occurrence: string) {
  const after = useAfterCodeFinding();
  return useMutation({
    mutationFn: async ({ because, fixedIn }: { because: string; fixedIn: number }) =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/fixed",
          {
            params: { path: { ...build, occurrence } },
            body: { because, fixed_in: fixedIn },
          },
        ),
      ),
    onSuccess: after,
  });
}

// A party, not a person: a team holds a code finding exactly as somebody does. Nobody
// hands it back.
export function useAssignCodeFinding(build: Build, occurrence: string) {
  const after = useAfterCodeFinding();
  return useMutation({
    mutationFn: async (held: { kind: "person" | "team"; identity: string } | null) =>
      unwrap(
        await api.PUT(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/assignment",
          {
            params: { path: { ...build, occurrence } },
            body:
              held === null
                ? {}
                : held.kind === "team"
                  ? { team: held.identity }
                  : { person: held.identity },
          },
        ),
      ),
    onSuccess: after,
  });
}

export function useSuppressionRules(product: string): UseQueryResult<SuppressionRule[]> {
  return useQuery({
    queryKey: ["suppression-rules", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/suppression-rules", {
          params: { path: { product } },
        }),
      ).items ?? [],
  });
}

export function useProposeSuppressionRule(product: string) {
  const after = useAfterCodeFinding();
  return useMutation({
    mutationFn: async (body: Body<"Propose-suppression-ruleRequest">) =>
      unwrap(
        await api.POST("/v1/products/{product}/suppression-rules", {
          params: { path: { product } },
          body,
        }),
      ),
    onSuccess: after,
  });
}

export function useApproveSuppressionRule(product: string) {
  const after = useAfterCodeFinding();
  return useMutation({
    mutationFn: async (id: number) =>
      unwrap(
        await api.POST("/v1/products/{product}/suppression-rules/{id}/approval", {
          params: { path: { product, id } },
        }),
      ),
    onSuccess: after,
  });
}

export function useRetireSuppressionRule(product: string) {
  const after = useAfterCodeFinding();
  return useMutation({
    mutationFn: async (id: number) =>
      unwrap(
        await api.DELETE("/v1/products/{product}/suppression-rules/{id}", {
          params: { path: { product, id } },
        }),
      ),
    onSuccess: after,
  });
}

export type FlawOffer = Body<"FlawOfferBody">;
type Recording = Body<"Record-code-finding-as-flawRequest">;

// What recording a confirmed code finding as a flaw is offered. Refused to somebody who does
// not triage both the internal code finding and the private flaw, which the screen
// asks before it reads this.
export function useFlawOffer(build: Build, occurrence: string, wanted: boolean) {
  return useQuery({
    queryKey: ["code-finding-flaw", build.product, build.branch_or_tag, build.variant, occurrence],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/flaw",
          { params: { path: { ...build, occurrence } } },
        ),
      ),
    enabled: wanted,
    retry: false,
  });
}

// Everything recording as a flaw or including in disclosure can change: the
// code finding, the queue, the decisions and a flaw that is now on the findings
// lists.
function useAfterRecordAsFlaw() {
  const queries = useQueryClient();
  const after = useAfterCodeFinding();
  return () => {
    void queries.invalidateQueries({ queryKey: ["code-finding-flaw"] });
    void queries.invalidateQueries({ queryKey: ["findings"] });
    after();
  };
}

export function useRecordAsFlaw(build: Build, occurrence: string) {
  const after = useAfterRecordAsFlaw();
  return useMutation({
    mutationFn: async (body: Recording) =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/flaw",
          { params: { path: { ...build, occurrence } }, body },
        ),
      ),
    onSuccess: after,
  });
}

// Withdraws the flaw a code finding was recorded as: the code finding is
// confirmed again, and its flaw is taken back out of every build as invalid.
export function useUndoRecordAsFlaw(build: Build, occurrence: string) {
  const after = useAfterRecordAsFlaw();
  return useMutation({
    mutationFn: async (because: string) =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/flaw/withdrawal",
          { params: { path: { ...build, occurrence } }, body: { because } },
        ),
      ),
    onSuccess: after,
  });
}

// Includes a code finding recorded as a flaw in its flaw's disclosure, or takes
// it back out.
export function useIncludeCodeFinding(build: Build, occurrence: string) {
  const after = useAfterRecordAsFlaw();
  const path =
    "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/flaw/disclosure" as const;
  return useMutation({
    mutationFn: async (include: boolean) =>
      unwrap(
        include
          ? await api.PUT(path, { params: { path: { ...build, occurrence } } })
          : await api.DELETE(path, { params: { path: { ...build, occurrence } } }),
      ),
    onSuccess: after,
  });
}
