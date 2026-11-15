// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { At } from "../ui/Decide";
import { serve } from "./mount";
import { PUBLISHED } from "./outcomes";

const REACH =
  "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/findings/{issue}/components/{component}/reach";

// One component at one build, as the decision form is opened on it.
export const DECIDING_AT: At = {
  product: "sonic",
  branch_or_tag: "master",
  variant: "broadcom",
  vulnerability: "CVE-2026-1",
  component: "openssl",
  version: "3.0.2",
};

// What a decision's reach says about the other builds holding the issue.
type Reach = { automatic: unknown[]; differing: unknown[] };

// The server a decision form reads from: a person with a thirty-day deferral
// threshold and the published outcomes, and a reach that names no other build
// unless one is given.
export function serveDecider(reach: Reach = { automatic: [], differing: [] }) {
  return serve((path) => {
    if (path === "/v1/session/me") {
      return {
        data: {
          identity: "ana",
          name: "Ana",
          admin: false,
          kind: "person",
          deferral_days: 30,
          outcomes: PUBLISHED,
        },
      };
    }
    if (path === REACH) return { data: reach };
    return { data: { items: [], total: 0 } };
  });
}
