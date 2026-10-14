// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import { unwrap } from "./queries";

// Where one issue sits, read once under one key by the issue screen and by the
// finding screen's affected-builds editor, so the cache holds one page size.
//
// The page is the most builds one edit of a flaw's builds may set. The editor
// sends the whole list, so its page has to be the whole answer whenever an
// edit is possible, and a larger answer is one it refuses to edit.
const ISSUE_PAGE = 200;

export function useIssue(vulnerability: string, enabled = true) {
  return useQuery({
    queryKey: ["issue", vulnerability],
    enabled,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/issues/{vulnerability}", {
          params: { path: { vulnerability }, query: { limit: ISSUE_PAGE } },
        }),
      ),
    retry: false,
  });
}
