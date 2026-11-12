// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import { unwrap } from "./queries";

// Where one issue sits in every product, as the issue screen reads it.
const ISSUE_PAGE = 200;

export function useIssue(vulnerability: string, enabled = true) {
  return useQuery({
    queryKey: ["issue", vulnerability],
    enabled,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/issues/{issue}", {
          params: { path: { issue: vulnerability }, query: { limit: ISSUE_PAGE } },
        }),
      ),
    retry: false,
  });
}

// The largest page the issue endpoint answers.
export const ISSUE_MOST = 500;

// Where one issue sits in one product, every row the endpoint answers: the
// affected-builds editor sends the product's whole list, so it needs that
// product's answer whole, whatever other products hold.
export function useIssueIn(vulnerability: string, product: string, enabled = true) {
  return useQuery({
    queryKey: ["issue", vulnerability, product],
    enabled,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/issues/{issue}", {
          params: { path: { issue: vulnerability }, query: { product, limit: ISSUE_MOST } },
        }),
      ),
    retry: false,
  });
}
