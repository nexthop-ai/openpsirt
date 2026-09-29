// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";

// The kind of flaw, by the classification the world uses.
//
// Suggested, never restricted. Anything may be recorded. A picker that
// refused an identifier it had not heard of would refuse next year's, and the
// point of recording these is to make a set of findings comparable to things
// outside this deployment — which is served by recording what somebody meant,
// not by having an opinion.
//
// The names come from the server, which holds the catalog's name for every
// weakness and a short one for the common ones. A screen shows the short name
// where there is one and the catalog's otherwise, whole, and the catalog's on
// hover.

export type Named = Body<"WeaknessBody">;

// What a screen calls a weakness: the short name where it has one, the
// catalog's otherwise, and nothing where neither list holds it.
export function called(named?: Named): string {
  return named?.short || named?.name || "";
}

// The two words a feed uses to say it has no classification. They are not
// classifications and drawing them as one tells a reader the flaw has been
// categorized as "other", which nobody decided.
const UNCLASSIFIED = new Set(["NVD-CWE-OTHER", "NVD-CWE-NOINFO"]);

export function unclassified(id: string): boolean {
  return UNCLASSIFIED.has(id.trim().toUpperCase());
}

// The place to read about it, built from the identifier rather than stored —
// the same way an issue's own record and a package's page are. Nothing is
// fetched. An identifier that is not a CWE number has nowhere to go, which
// includes the two words above.
export function readAbout(id: string): string | null {
  const number = /^CWE-(\d+)$/.exec(id.trim().toUpperCase());
  if (!number) return null;
  return `https://cwe.mitre.org/data/definitions/${number[1]}.html`;
}

// The most a recorded flaw states, which the server refuses past.
export const MOST_WEAKNESSES = 16;

// A typed weakness as the server takes it: CWE- and a number from one. A bare
// number is read as that CWE. Anything else is null, because the record
// would be refused whole over it.
export function asWeakness(typed: string): string | null {
  const clean = typed.trim().toUpperCase();
  const shaped = /^(?:CWE-)?([1-9][0-9]{0,5})$/.exec(clean);
  return shaped ? `CWE-${shaped[1]}` : null;
}

// The weaknesses a search finds, most common first. Nothing typed is the
// common ones, which is what a picker offers before anybody types.
export function useWeaknessSearch(typed: string, enabled = true) {
  const q = typed.trim();
  return useQuery({
    enabled,
    queryKey: ["weaknesses", "search", q],
    queryFn: async () =>
      unwrap(await api.GET("/v1/weaknesses", { params: { query: q ? { q } : {} } })).items ?? [],
    staleTime: Infinity,
    retry: false,
  });
}

// The names of the identifiers given, keyed by the identifier as asked. Asked
// only where there is something to name.
export function useWeaknessNames(ids: string[]): Map<string, Named> {
  const asked = [...new Set(ids.map((each) => each.trim()).filter(Boolean))].sort();
  const got = useQuery({
    enabled: asked.length > 0,
    queryKey: ["weaknesses", "named", asked],
    queryFn: async () =>
      unwrap(await api.GET("/v1/weaknesses", { params: { query: { id: asked } } })).items ?? [],
    staleTime: Infinity,
    retry: false,
  });
  const out = new Map<string, Named>();
  for (const one of got.data ?? []) {
    for (const each of asked) {
      if (each.toUpperCase() === one.id) out.set(each, one);
    }
  }
  return out;
}
