// A version shared by every component at one level of the dependency tree.
//
// A version shared by components of *different names* is not describing any of
// them. It is the producer describing the build — a build identifier, a batch
// stamp — and drawn on every row it is noise that makes the level unreadable
// while telling the reader nothing they could act on. The real case is a
// switch image whose containers all carry one stamp where a version should be.
//
// Returns the shared version, or empty where there is none. The caller draws
// it once above the level and leaves it off those rows.
export function sharedVersion(kids: { version: string }[]): string {
  // Components with no version are left out of the decision. They draw
  // nothing either way, and counting them as disagreement is how this missed
  // the case it was written for: the switch image's root has one child with
  // no version beside twenty-nine containers all carrying the same stamp.
  const versioned = kids.filter((kid) => kid.version !== "");
  // One entry is not a level. A single component's version is its own, and
  // moving it above the row would say something about a level of one.
  const first = versioned.length < 2 ? "" : versioned[0]?.version;
  if (!first) return "";
  return versioned.every((kid) => kid.version === first) ? first : "";
}
