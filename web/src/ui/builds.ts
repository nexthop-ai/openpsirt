// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// One build of one product, as a string a checkbox set or a React list can be
// keyed on.
//
// Here rather than in each screen that needs it, because a key assembled
// without the separator makes a build named `main` with the variant `arm` at
// version `64` and one named `main` with the variant `arm64` at no version the
// same string, and two rows in one list share a key.
//
// Always three parts, with the version empty where there is none. `+ undefined`
// appends the text "undefined" rather than nothing.

// Not a character any of the three names can hold, so a key cannot be two
// builds.
const APART = "\u0000";

export function buildKey(row: { stream?: string; variant?: string }, version?: string): string {
  return [row.stream ?? "", row.variant ?? "", version ?? ""].join(APART);
}

export function fromBuildKey(key: string): { stream: string; variant: string; version: string } {
  const [stream = "", variant = "", version = ""] = key.split(APART);
  return { stream, variant, version };
}
