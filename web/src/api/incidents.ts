// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useInvalidating } from "./invalidate";

// Everything an act on an incident can move: the incidents list, which Home's
// tile and a finding's shelf read too, and the finding it stands on.
const afterIncident = ["incidents", "finding"] as const;

export function useAfterIncident() {
  return useInvalidating(afterIncident);
}
