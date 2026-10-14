// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A file's size, in megabytes from one up and whole kilobytes below, never
// less than one kilobyte. A picked file and an attached one are said alike.
export function sizeSaid(bytes: number): string {
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}
