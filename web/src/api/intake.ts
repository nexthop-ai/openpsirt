import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";

// What arrived, what it was judged to be, and the rulings some of those
// judgments wait on.
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

// Everything an act on a report or a ruling can move.
export function useAfterReport() {
  const queries = useQueryClient();
  return () => {
    void queries.invalidateQueries({ queryKey: ["reports"] });
    void queries.invalidateQueries({ queryKey: ["recorded-report"] });
    void queries.invalidateQueries({ queryKey: ["rulings"] });
    void queries.invalidateQueries({ queryKey: ["duplicates"] });
    void queries.invalidateQueries({ queryKey: ["report"] });
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
// the review queue and the record narrow what they list.
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
        await api.GET("/v1/products/{product}/issues/{vulnerability}/duplicates", {
          params: { path: { product, vulnerability } },
        }),
      ),
    // Refused to anybody who may not work reports, which is an answer.
    retry: false,
  });
}

export function useRecordReport(product: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async (body: Body<"ClaimedBody">) =>
      unwrap(
        await api.POST("/v1/products/{product}/reports", {
          params: { path: { product } },
          body,
        }),
      ),
    onSuccess: after,
  });
}

export function useAcknowledgeReport(product: string, reference: string) {
  const after = useAfterReport();
  return useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/reports/{reference}/acknowledgement", {
          params: { path: { product, reference } },
        }),
      ),
    onSuccess: after,
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
// claims the review queue counts.
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
