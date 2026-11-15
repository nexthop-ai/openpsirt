// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { QueryClient } from "@tanstack/react-query";
import type { Who } from "../app/session";
import { client } from "./mount";
import { SCOPE_KEPT } from "../app/drafts";

type Can = NonNullable<Who["reach"]>[number];

// One product in a session's reach, holding nothing but what is named.
export function reaching(product: string, holds: Partial<Can> = {}): Can {
  return {
    product,
    name: product,
    may_see: false,
    may_triage: false,
    may_assign: false,
    may_hide: false,
    may_agree: false,
    may_approve_rulings: false,
    agrees_private: false,
    agrees_public: false,
    agrees_security_testing: false,
    reads_private: false,
    reads_public: false,
    reads_security_testing: false,
    triages_public: false,
    triages_security_testing: false,
    ...holds,
  };
}

// A product whose dependency findings the reader reads whole.
export function readingDependencies(product: string): Can {
  return reaching(product, { may_see: true, reads_public: true, reads_private: true });
}

// A person reading one product's dependency findings whole, and holding
// nothing else.
export function readerOf(product: string): Who {
  return {
    identity: "ana",
    name: "Ana",
    admin: false,
    kind: "person",
    reach: [readingDependencies(product)],
  } as Who;
}

// A person reading one product's security testing code findings, or not,
// with the scope picked and the session already held, as the app's is by the
// time a screen draws. The session is answered beside the screen's own reads.
export function codeReader(
  reads: boolean,
  scope: Record<string, string> = { product: "sonic" },
  holds: Partial<Can> = {},
): { session: Who; queries: QueryClient } {
  window.sessionStorage.setItem(SCOPE_KEPT, JSON.stringify(scope));
  const session = {
    identity: "ana",
    name: "Ana",
    kind: "person",
    reach: [reaching(scope.product ?? "sonic", { reads_security_testing: reads, ...holds })],
    outcomes: [],
  } as unknown as Who;
  const queries = client();
  queries.setQueryData(["whoami"], session);
  return { session, queries };
}
