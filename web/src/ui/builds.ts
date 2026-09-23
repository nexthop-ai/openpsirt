// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// One build of one product, as a string a checkbox set or a React list can be
// keyed on.
//
// Here rather than in the two screens that need it, because it was in both:
// the separator declared twice with the same comment, the key assembled three
// ways in five places, and two of the five leaving the separator out
// altogether — so a build named `main` with the variant `arm` at version `64`
// and one named `main` with the variant `arm64` at no version produced the
// same string, and two rows in one list shared a key.
//
// Always three parts, with the version empty where there is none. `+ undefined`
// appends the text "undefined" rather than nothing, which is how a version
// went missing from a key that looked like it carried one.

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
