// What a list of upgrade candidates says about itself.
//
// The flag changes what the count means rather than what it says. Ranked, a
// version's number is everything reaching it would close; unranked, it is only
// what that release fixed, because nothing established which release follows
// which. The two read alike on screen, so the screen has to say which one it
// is drawing.
//
// Kept here rather than beside each table, because three places draw this and
// a wording that differs between them reads as three different facts.

// An ordering held by a set of candidates. An answer that has not arrived is
// not a ranking: a count drawn as though it were ordered, off a list that
// failed to read, is an authoritative claim about nothing.
export function ranked(upgrades: readonly { ordered?: boolean }[]): boolean {
  return upgrades[0]?.ordered ?? false;
}

// The label on the list.
export function rankedLabel(ordered: boolean): string {
  return ordered ? "Furthest along first" : "Not ranked";
}

// Why, on hover, on the thing it is about.
export function rankedWhy(ordered: boolean): string {
  return ordered
    ? "A later release carries the earlier fixes too, so the first closes the most."
    : "Each count is what that release fixed itself, because these versions could not be put in order.";
}

// What one candidate's count is counting. Named rather than left to the
// number, which is the same number in both states whenever a release is the
// only one that fixes anything.
export function upgradeCount(
  up: { ordered?: boolean; reached?: number; fixed_here?: number },
  own = "",
): string {
  return up.ordered
    ? `closes ${(up.reached ?? 0).toLocaleString()}`
    : `fixed ${(up.fixed_here ?? 0).toLocaleString()}${own}`;
}
