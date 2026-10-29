// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Who } from "../app/session";

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
