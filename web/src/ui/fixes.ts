// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Body } from "../api/client";

type Fix = Body<"FixBody">;

// What a named fix release's latest scans say about the issue, as a fact and
// nothing more. An issue absent from a scan is not called fixed, and one still
// present is not called a failed fix: the scanner may be wrong either way.
export function scanState(fix: Pick<Fix, "scanned" | "open">): string {
  if (fix.open) return "open in its latest scans";
  if (fix.scanned) return "not found in its latest scans";
  return "not scanned";
}
