// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import { unwrap } from "./queries";
import { buildKey } from "../ui/builds";

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

// The most builds one write of an issue's affected builds names.
export const BUILDS_MOST = 200;

// Where one issue sits in one product, every row the endpoint answers: the
// affected-builds editor sends the product's whole list, so it reads the
// product's answer a page at a time until it holds every row. It stops once
// the rows name more builds than one write takes, since the editor writes
// nothing past that bound.
export function useIssueIn(vulnerability: string, product: string, enabled = true) {
  return useQuery({
    queryKey: ["issue", vulnerability, product],
    enabled,
    queryFn: async () => {
      const ask = async (offset: number) =>
        unwrap(
          await api.GET("/v1/issues/{issue}", {
            params: {
              path: { issue: vulnerability },
              query: { product, limit: ISSUE_MOST, offset },
            },
          }),
        );
      const first = await ask(0);
      const items = [...(first.items ?? [])];
      const builds = new Set(items.map((row) => buildKey(row)));
      while (items.length < first.total && builds.size <= BUILDS_MOST) {
        const next = (await ask(items.length)).items ?? [];
        if (next.length === 0) break;
        items.push(...next);
        for (const row of next) builds.add(buildKey(row));
      }
      return { ...first, items };
    },
    retry: false,
  });
}
