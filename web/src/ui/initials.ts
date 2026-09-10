// The two letters standing for somebody where there is no room for a name.
//
// One function, because there were three and they had drifted: two split an
// address on the `@` and one did not, so `alice@example.com` was "AE" on a
// finding and in the work list and "AC" in the rail — the same person with two
// avatars on one screen, which reads as two people.
//
// The provider prefix goes first: an identity is written `provider:username`,
// and taking the first letters of "proxy" says nothing about anybody. What is
// left is split on the separators a username actually uses, the `@` among
// them, so a mail address gives the local part rather than the domain.
export function initials(name: string): string {
  const parts = name
    .replace(/^[a-z]+:/, "")
    .split(/[\s._@-]+/)
    .filter(Boolean);
  if (parts.length === 0) {
    return "?";
  }
  if (parts.length === 1) {
    return (parts[0] ?? "").slice(0, 2).toUpperCase();
  }
  return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? "")).toUpperCase();
}
