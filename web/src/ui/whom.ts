// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A person's form in a picker, and the resolution of what was typed.
//
// The name is what somebody recognizes and the identity is what the server
// takes, so an offer carries both where they differ: two colleagues can share
// a display name, and a picker offering only that would resolve to whichever
// of them the list happened to hold first.

export type Person = { identity?: string; name?: string };

// The form one person is offered as.
export function offeredAs(person: Person): string {
  const identity = person.identity ?? "";
  const name = person.name ?? "";
  if (!name || name === identity) return identity;
  return `${name} (${identity})`;
}

// The identity behind what was typed, or empty where it is nobody offered.
//
// Empty is what keeps the button disabled. Neither picker can bring anybody
// into the deployment, so a name matching nobody is refused by the server —
// and being refused after typing is a worse way to learn that than not being
// offered it in the first place.
export function whoIs(typed: string, people: Person[]): string {
  const asked = typed.trim().toLowerCase();
  if (asked === "") return "";
  for (const person of people) {
    if (offeredAs(person).toLowerCase() === asked) return person.identity ?? "";
  }
  // The identity on its own, for somebody who knows it and typed it.
  for (const person of people) {
    if ((person.identity ?? "").toLowerCase() === asked) return person.identity ?? "";
  }
  return "";
}

// The people whose name or identity contains what is typed, ignoring capitals
// — the same rule the server matches on, so a list narrowed here and one
// narrowed there hold the same people.
export function matching(typed: string, people: Person[]): Person[] {
  const asked = typed.trim().toLowerCase();
  if (asked === "") return people;
  return people.filter(
    (person) =>
      (person.identity ?? "").toLowerCase().includes(asked) ||
      (person.name ?? "").toLowerCase().includes(asked),
  );
}
