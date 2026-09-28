// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The address a report's file is fetched from: the report's path with the
// format as its extension, and the same question the screen asked. A browser
// fetches it directly, so it is a link rather than a call through the client.
export function exportAt(
  path: string,
  format: "csv" | "json",
  query?: URLSearchParams | string,
): string {
  const asked = query === undefined ? "" : query.toString();
  return `${path}.${format}${asked ? `?${asked}` : ""}`;
}
