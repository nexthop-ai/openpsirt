// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The roles, with what each allows — the same words the API reference uses.
//
// A bare token in a list is what showing a justification in words fixed, and
// the same defect was here: `private-triage` and
// `private-read` differ by one word in a select, and what they differ by is
// whether somebody can decide about findings nobody has announced. The label
// says what it is; the meaning says what granting it does.
export const ROLES = [
  {
    role: "public-read",
    label: "Read, public",
    means: "Read findings about issues that are public",
    grants: true,
  },
  {
    role: "private-read",
    label: "Read, private",
    means: "Read findings nobody has announced. Public ones need their own role",
    grants: true,
  },
  {
    role: "public-triage",
    label: "Triage, public",
    means: "Decide, revise, withdraw and comment on public findings; take work nobody owns",
    grants: true,
  },
  {
    role: "private-triage",
    label: "Triage, private",
    means:
      "The same for findings nobody has announced, including recording one. Public ones need their own role",
    grants: true,
  },
  {
    role: "approver",
    label: "Approver",
    means: "Agree to somebody else's claim. Never their own",
    grants: false,
  },
  {
    role: "assigner",
    label: "Assigner",
    means: "Give work to somebody else, or take what they are holding",
    grants: false,
  },
] as const;

export type Role = (typeof ROLES)[number]["role"];

// The name for one, wherever a stored role is read back. A role this does not
// know is shown as it arrived: a deployment that grows one before the
// interface does should leave somebody reading something unfamiliar rather
// than a blank.
export function called(role?: string): string {
  return ROLES.find((each) => each.role === role)?.label ?? role ?? "";
}

// A role's own reach. Approver and assigner are
// capabilities bounded by what their holder may read, so granted alone they
// reach nothing — which was accepted in silence and read as working until
// somebody signed in to an empty tool.
function reaches(role?: string): boolean {
  return ROLES.find((each) => each.role === role)?.grants ?? true;
}

// The grants that bear on one product: a role on the product itself,
// or one held across the estate.
export type Holding = { role?: string; effective?: boolean; everywhere?: boolean };

// A grant that gives somebody nothing at all: a capability,
// on a product where they hold no role that reaches anything.
//
// An estate grant counts. A read held everywhere is a read held here, so a
// capability granted beside one reaches something. The caller narrows to what
// bears on the product, because it is the thing that knows how a product is
// spelled in each place: a held role names it as it is shown and a grant names
// it as the API takes it.
//
// A withdrawn grant is not held. Counting one would say somebody reads a
// product because they used to.
export function wouldReachNothing(role: string, bearing: Holding[]): boolean {
  if (reaches(role)) return false;
  return !bearing.some((held) => held.effective !== false && reaches(held.role));
}
