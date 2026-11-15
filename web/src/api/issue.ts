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

// The most builds one write of an issue's affected builds names, and the most
// the read beside it answers.
export const BUILDS_MOST = 200;

// The builds of one product where an issue stands open, in one read and in the
// shape the affected-builds write takes, with whether more stand open than one
// write names.
export function useAffectedBuilds(vulnerability: string, product: string, enabled = true) {
  return useQuery({
    queryKey: ["issue", vulnerability, product],
    enabled,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{issue}/builds", {
          params: { path: { product, issue: vulnerability } },
        }),
      ),
    retry: false,
  });
}
