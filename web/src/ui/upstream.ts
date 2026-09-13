// Where a package lives upstream, worked out from the identifier it ships under.
//
// Nothing is fetched and nothing is stored: a package identifier already names
// the ecosystem and the name within it, and each ecosystem has one address
// where a package is read about. The same technique the issue records use —
// built from what is known rather than supplied by a scanner.
//
// **A name is put in the path, so it is encoded.** A package identifier comes
// from a scan file, and a name carrying a slash or a question mark would
// otherwise choose part of somebody else's address.

// Where each ecosystem's packages are read about. Absent means no address is
// offered rather than a guessed one: a private registry and a vendored fork
// both look like a package whose ecosystem this does not know.
const WHERE: Record<string, (name: string) => string> = {
  // The module index, which resolves every module path including the ones that
  // are not repository addresses.
  golang: (name) => "https://pkg.go.dev/" + path(name),
  npm: (name) => "https://www.npmjs.com/package/" + path(name),
  pypi: (name) => "https://pypi.org/project/" + segment(name) + "/",
  cargo: (name) => "https://crates.io/crates/" + segment(name),
  // The distribution's own tracker, which is where a Debian package's history,
  // its maintainer and its open bugs are.
  deb: (name) => "https://tracker.debian.org/pkg/" + segment(name),
  rpm: (name) => "https://src.fedoraproject.org/rpms/" + segment(name),
};

// upstream is where to read about the package an identifier names.
export function upstream(purl: string | undefined | null): string | null {
  const parsed = readPurl(purl);
  if (!parsed) return null;
  const at = WHERE[parsed.ecosystem];
  return at ? at(parsed.name) : null;
}

// named is the package's own name within its ecosystem, without the namespace
// a distribution puts in front of it.
export function named(purl: string | undefined | null): string {
  return readPurl(purl)?.name ?? "";
}

// readPurl pulls the ecosystem and the name out of a package identifier.
//
// The namespace stays part of the name where the ecosystem's own addresses
// include it — a Go module path and a scoped npm package are both several
// segments — and is dropped where they do not: a Debian package is read about
// under its own name, not under "debian/".
function readPurl(purl: string | undefined | null): { ecosystem: string; name: string } | null {
  const written = String(purl ?? "").trim();
  if (!written.toLowerCase().startsWith("pkg:")) return null;
  // The version and any qualifiers say nothing about where to read. The
  // version follows the *last* separator, because a scoped package name begins
  // with one: splitting on the first leaves "@types/node" as no name at all.
  let body = written.slice(4).split("?")[0] ?? "";
  const version = body.lastIndexOf("@");
  if (version > 0) body = body.slice(0, version);
  const parts = body.split("/").filter((each) => each !== "");
  if (parts.length < 2) return null;
  const ecosystem = (parts[0] ?? "").toLowerCase();
  const rest = parts.slice(1);
  // A distribution puts its own name first, and the package is read about
  // under the name after it.
  const name =
    ecosystem === "deb" || ecosystem === "rpm" ? (rest[rest.length - 1] ?? "") : rest.join("/");
  if (!name) return null;
  return { ecosystem, name: decode(name) };
}

function decode(name: string): string {
  try {
    return decodeURIComponent(name);
  } catch {
    // A name that is not valid escaping is used as it stands rather than
    // dropped: it is still the name, and encoding it again is what makes it
    // safe to put in a path.
    return name;
  }
}

// path encodes a name that may contain separators, keeping them.
function path(name: string): string {
  return name.split("/").map(encodeURIComponent).join("/");
}

// segment encodes a name that is one path segment.
function segment(name: string): string {
  return encodeURIComponent(name);
}
