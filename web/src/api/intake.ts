// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";

// What arrived, what it was judged to be, and the rulings some of those
// decisions wait on.
//
// One module, because every act here moves more than one read: a ruling
// changes the report list, the report, the waiting list and the duplicates an
// issue shows.

export type Report = Body<"ReportBody">;
export type Ruling = Body<"RulingBody">;
export type Disposition = NonNullable<Report["disposition"]>;
export type Rulable = Ruling["disposition"];

// The rows one request carries, named so the pager and the request agree.
export const PAGE = 50;

// Everything an act on a report or a ruling can move. A duplicate ruling moves
// an issue's disclosure date, and withdrawing one moves it back, so every read
// carrying that date is among them. A decision takes a report out of the held
// lists and the holdings counted beside them.
export function useAfterReport() {
  const queries = useQueryClient();
  return () => {
    void queries.invalidateQueries({ queryKey: ["held-reports"] });
    void queries.invalidateQueries({ queryKey: ["holdings"] });
    void queries.invalidateQueries({ queryKey: ["reports"] });
    void queries.invalidateQueries({ queryKey: ["recorded-report"] });
    void queries.invalidateQueries({ queryKey: ["rulings"] });
    void queries.invalidateQueries({ queryKey: ["duplicates"] });
    void queries.invalidateQueries({ queryKey: ["report"] });
    void queries.invalidateQueries({ queryKey: ["duplicate-disclosure"] });
    void queries.invalidateQueries({ queryKey: ["finding"] });
    void queries.invalidateQueries({ queryKey: ["findings"] });
    void queries.invalidateQueries({ queryKey: ["issue"] });
    void queries.invalidateQueries({ queryKey: ["disclosure-deadlines"] });
    void queries.invalidateQueries({ queryKey: ["home"] });
  };
}

export function useReports(
  product: string,
  offset: number,
): UseQueryResult<{ items: Report[] | null; total?: number }> {
  return useQuery({
    queryKey: ["reports", product, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/reports", {
          params: { path: { product }, query: { limit: PAGE, offset } },
        }),
      ),
  });
}

export function useReport(product: string, reference: string): UseQueryResult<Report> {
  return useQuery({
    queryKey: ["recorded-report", product, reference],
    // Nothing to ask for until both names are known, which is the ordinary
    // case on the record form opened from anywhere but a report.
    enabled: product !== "" && reference !== "",
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/reports/{reference}", {
          params: { path: { product, reference } },
        }),
      ),
    retry: false,
  });
}

export function useRulings(
  product: string,
  waiting: boolean,
  offset: number,
  enabled = true,
): UseQueryResult<{ items: Ruling[] | null; total?: number }> {
  return useQuery({
    enabled,
    queryKey: ["rulings", product, waiting, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/report-rulings", {
          params: { path: { product }, query: { waiting, limit: PAGE, offset } },
        }),
      ),
  });
}

// Rulings in every product the reader may work reports in, narrowed the way
// the review queue and the audit log narrow what they list.
export function useRulingsAcross(asked: {
  waiting?: boolean;
  approvable?: boolean;
  products?: string[];
  from?: string;
  to?: string;
  offset?: number;
  limit?: number;
}): UseQueryResult<{ items: Ruling[] | null; total?: number }> {
  return useQuery({
    queryKey: ["rulings", "across", asked],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/report-rulings", {
          params: {
            query: {
              limit: asked.limit ?? PAGE,
              offset: asked.offset ?? 0,
              ...(asked.waiting ? { waiting: true } : {}),
              ...(asked.approvable ? { approvable: true } : {}),
              ...(asked.products && asked.products.length > 0 ? { product: asked.products } : {}),
              ...(asked.from ? { from: asked.from } : {}),
              ...(asked.to ? { to: asked.to } : {}),
            },
          },
        }),
      ),
  });
}

export function useRuling(product: string, ruling: number | undefined): UseQueryResult<Ruling> {
  return useQuery({
    enabled: !!ruling,
    queryKey: ["rulings", product, "one", ruling],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/report-rulings/{ruling}", {
          params: { path: { product, ruling: ruling ?? 0 } },
        }),
      ),
  });
}

export function useReportFiles(product: string, reference: string) {
  return useQuery({
    queryKey: ["recorded-report", product, reference, "files"],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/reports/{reference}/attachments", {
          params: { path: { product, reference } },
        }),
      ),
  });
}

export function useDuplicates(product: string, vulnerability: string) {
  return useQuery({
    queryKey: ["duplicates", product, vulnerability],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{issue}/duplicates", {
          params: { path: { product, issue: vulnerability } },
        }),
      ),
    // Refused to anybody who may not work reports, which is an answer.
    retry: false,
  });
}

export function useRecordReport(product: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (body: Body<"NewReportBody">) =>
      unwrap(
        await api.POST("/v1/products/{product}/reports", {
          params: { path: { product } },
          body,
        }),
      ),
    onSuccess: after,
  });
}

// A report's case: what it said before an edit, what was written to and
// from the reporter, the notes on it, and every act on it.

export type Message = Body<"MessageBody">;
export type ReportEvent = Body<"ReportEventBody">;

export function useEditReport(product: string, reference: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (body: Body<"ReportEditBody">) =>
      unwrap(
        await api.PUT("/v1/products/{product}/reports/{reference}", {
          params: { path: { product, reference } },
          body,
        }),
      ),
    onSuccess: after,
  });
}

export function useRevisions(product: string, reference: string, enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["recorded-report", product, reference, "revisions"],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/reports/{reference}/revisions", {
          params: { path: { product, reference } },
        }),
      ),
  });
}

export function useMessages(product: string, reference: string) {
  return useQuery({
    queryKey: ["recorded-report", product, reference, "messages"],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/reports/{reference}/messages", {
          params: { path: { product, reference } },
        }),
      ),
    retry: false,
  });
}

export function useLogMessage(product: string, reference: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (body: Body<"MessageLogBody">) =>
      unwrap(
        await api.POST("/v1/products/{product}/reports/{reference}/messages", {
          params: { path: { product, reference } },
          body,
        }),
      ),
    onSuccess: after,
  });
}

export function useReportNotes(product: string, reference: string) {
  return useQuery({
    queryKey: ["recorded-report", product, reference, "notes"],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/reports/{reference}/notes", {
          params: { path: { product, reference } },
        }),
      ),
    retry: false,
  });
}

export function useNoteOnReport(product: string, reference: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (body: string) =>
      unwrap(
        await api.POST("/v1/products/{product}/reports/{reference}/notes", {
          params: { path: { product, reference } },
          body: { body },
        }),
      ),
    onSuccess: after,
  });
}

// The edit a report note's thread asks for, bound to its report so the
// thread's own shape stays the one every thread shares.
export function editReportNote(product: string, reference: string) {
  return function useEditReportNote() {
    const after = useAfterReport();
    return useMutation({
      mutationFn: async ({ id, body }: { id: number; body: string }) =>
        unwrap(
          await api.PUT("/v1/products/{product}/reports/{reference}/notes/{note}", {
            params: { path: { product, reference, note: id } },
            body: { body },
          }),
        ),
      onSuccess: after,
    });
  };
}

export function reportNoteHistory(product: string, reference: string) {
  return function useReportNoteHistory(note: number) {
    return useQuery({
      queryKey: ["recorded-report", product, reference, "notes", note, "history"],
      queryFn: async () =>
        unwrap(
          await api.GET("/v1/products/{product}/reports/{reference}/notes/{note}/history", {
            params: { path: { product, reference, note } },
          }),
        ),
    });
  };
}

export function useReportHistory(product: string, reference: string) {
  return useQuery({
    queryKey: ["recorded-report", product, reference, "history"],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/reports/{reference}/history", {
          params: { path: { product, reference } },
        }),
      ),
  });
}

export function useAssignReport(product: string, reference: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (body: Body<"Assign-reportRequest">) =>
      unwrap(
        await api.PUT("/v1/products/{product}/reports/{reference}/assignment", {
          params: { path: { product, reference } },
          body,
        }),
      ),
    onSuccess: after,
  });
}

// What a hand-back moves: who holds work, every list of held or unheld work,
// and Home. Withdrawing a role, a team change and a deactivation hand work
// back as well, so each refreshes these beside its own lists.
export const handedBack = [
  "holdings",
  "held-reports",
  "findings",
  "leads",
  "reports",
  "assigned",
  "team-assigned",
  "home",
];

export function useAfterHandBack() {
  const queries = useQueryClient();
  return () => {
    for (const key of handedBack) {
      void queries.invalidateQueries({ queryKey: [key] });
    }
  };
}

// Everything one person holds handed back to nobody: their findings and their
// open reports.
export function useHandBack() {
  const after = useAfterHandBack();
  return useMutation({
    mutationFn: async (identity: string) =>
      unwrap(
        await api.POST("/v1/people/{identity}/assignments/hand-back", {
          params: { path: { identity } },
          body: {},
        }),
      ),
    onSuccess: after,
  });
}

// Open reports by who holds them: one person and their teams' queues, one
// team's queue, or nobody. In one product, or every product where the reader
// reads reports.
export function useHeldReports(
  whose: { person: string } | { team: string } | "nobody",
  product: string | undefined,
  offset = 0,
  enabled = true,
): UseQueryResult<{ items: Body<"HeldReportBody">[] | null; total?: number }> {
  return useQuery({
    enabled,
    queryKey: ["held-reports", whose, product ?? "", offset],
    queryFn: async () => {
      const query = { limit: PAGE, offset, ...(product ? { product } : {}) };
      if (whose === "nobody") {
        return unwrap(await api.GET("/v1/unassigned/reports", { params: { query } }));
      }
      if ("team" in whose) {
        return unwrap(
          await api.GET("/v1/teams/{team}/assignments/reports", {
            params: { path: { team: whose.team }, query },
          }),
        );
      }
      return unwrap(
        await api.GET("/v1/people/{identity}/assignments/reports", {
          params: { path: { identity: whose.person }, query },
        }),
      );
    },
  });
}

export function useAcceptReport(product: string, reference: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (vulnerability: string) =>
      unwrap(
        await api.PUT("/v1/products/{product}/reports/{reference}/issue", {
          params: { path: { product, reference } },
          body: { vulnerability },
        }),
      ),
    onSuccess: after,
  });
}

// The disclosure date ruling these reports a duplicate of an issue would
// start, absent where it would start none. Nothing is asked until the issue
// and the reports are named.
export function useDuplicateStarts(
  product: string,
  issue: string,
  reports: string[],
): UseQueryResult<Body<"DuplicateDisclosureBody">> {
  return useQuery({
    queryKey: ["duplicate-disclosure", product, issue, reports],
    enabled: product !== "" && issue !== "" && reports.length > 0,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{issue}/duplicate-disclosure", {
          params: { path: { product, issue }, query: { report: reports } },
        }),
      ),
    retry: false,
  });
}

export function useRule(product: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (body: Body<"RulingProposedBody">) =>
      unwrap(
        await api.POST("/v1/products/{product}/report-rulings", {
          params: { path: { product } },
          body,
        }),
      ),
    onSuccess: after,
  });
}

export function useApproveRuling(product: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (ruling: number) =>
      unwrap(
        await api.POST("/v1/products/{product}/report-rulings/{ruling}/approval", {
          params: { path: { product, ruling } },
        }),
      ),
    onSuccess: after,
  });
}

export function useWithdrawRuling(product: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (ruling: number) =>
      unwrap(
        await api.POST("/v1/products/{product}/report-rulings/{ruling}/withdrawal", {
          params: { path: { product, ruling } },
        }),
      ),
    onSuccess: after,
  });
}

// uploadReportFile stores one file against a report, held at once: a report
// carries no text a reference could be written into.
export async function uploadReportFile(product: string, reference: string, file: File) {
  const form = new FormData();
  form.append("file", file);
  return unwrap(
    await api.POST("/v1/products/{product}/reports/{reference}/attachments", {
      params: { path: { product, reference } },
      body: form as never,
      bodySerializer: (body: unknown) => body as FormData,
    }),
  );
}

// useApprovable is how many rulings this reader may agree to, in one product
// or across every product: waiting, proposed by somebody else, where they may
// approve a ruling. What a count of what is pending their approval adds to the
// decisions the review queue counts.
export function useApprovable(product?: string): UseQueryResult<number> {
  return useQuery({
    queryKey: ["rulings", "approvable", product ?? ""],
    refetchInterval: 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/report-rulings", {
          params: {
            query: { limit: 1, approvable: true, ...(product ? { product: [product] } : {}) },
          },
        }),
      ).total ?? 0,
  });
}
