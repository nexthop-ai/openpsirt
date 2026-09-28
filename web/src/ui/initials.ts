// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The two letters standing for somebody where there is no room for a name.
//
// One function, so one person has one avatar on every screen.
//
// An identity is a username, so it is split on the separators a username
// actually uses. A mail address gives its local part: the domain is shared by
// everybody at one organization, and a letter taken from it tells nobody apart.
export function initials(name: string): string {
  const local = name.split("@")[0] ?? "";
  const parts = local.split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) {
    return "?";
  }
  if (parts.length === 1) {
    return (parts[0] ?? "").slice(0, 2).toUpperCase();
  }
  return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? "")).toUpperCase();
}
