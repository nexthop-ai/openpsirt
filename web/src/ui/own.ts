// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A table's own entry for a word, or nothing.
//
// Asked through a guard rather than by indexing: an object literal inherits
// from the prototype, so a server-supplied word naming a member of it —
// `constructor`, `toString` — is a function, and the optional chain that guards
// the lookup does not guard what is read from it after.
export function own<T>(table: Readonly<Record<string, T>>, word?: string | null): T | undefined {
  const key = word ?? "";
  return Object.hasOwn(table, key) ? table[key] : undefined;
}
