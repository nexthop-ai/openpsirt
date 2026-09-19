package currency

import (
	"net/url"
	"strings"
	"time"
)

// Asked reads the ecosystem and the name to ask it, out of a package
// identifier.
//
// Only the identifier is read. A component's own name is what a producer chose
// to call it, and the indexes here are keyed on what the ecosystem calls it —
// which for a Go module is a path and for a scoped npm package is two segments
// that have to arrive as one name.
//
// The second return says whether there is anything to ask at all. A component
// with no identifier, or one in an ecosystem with no index we ask, is not a
// failure: a distribution package, a private module and a vendored fork all
// look like this.
func Asked(purl string) (ecosystem, name string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !found {
		return "", "", false
	}
	// Everything after the path is somebody else's business: qualifiers first,
	// then a subpath, which may itself contain the separators below.
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")

	ecosystem, path, found := strings.Cut(rest, "/")
	if !found || path == "" {
		return "", "", false
	}
	ecosystem = strings.ToLower(ecosystem)

	// The version is cut from the right: a namespace may contain no "@", but
	// an npm scope begins with one, so the last is the separator.
	if at := strings.LastIndex(path, "@"); at > 0 {
		path = path[:at]
	}

	// Each segment is decoded on its own, so the separators between them
	// survive as separators: each asker then joins the name the way its own
	// protocol requires — the module proxy keeps them, and the npm registry
	// escapes every one, which is what a scoped package needs.
	//
	// An escaped separator inside a segment does not survive that, and the
	// comment here used to claim it did. It cannot: the parts are rejoined
	// with the character that was escaped, so nothing downstream can tell
	// which of them was content. No ecosystem asked here has a name
	// containing one — a module path's slashes are all separators and an npm
	// scope is two segments — so the ambiguity is stated rather than solved.
	//
	// A segment that will not decode is a refusal rather than a segment kept
	// raw. Kept, a malformed escape became part of the name asked about, and
	// what came back was an answer about a different package or no package at
	// all — recorded either way as this component's upstream version.
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		unescaped, err := url.PathUnescape(segment)
		if err != nil {
			return "", "", false
		}
		segments[i] = unescaped
	}
	name = strings.Join(segments, "/")
	if name == "" {
		return "", "", false
	}
	return ecosystem, name, true
}

// Identified reads the year an issue was identified in, out of its identifier.
//
// Zero where the identifier does not name one. CVE and several others begin
// with a year; GHSA and a handful more do not, and guessing for those would
// invent the very fact this is here to supply.
func Identified(identifier string) int {
	for _, part := range strings.Split(identifier, "-") {
		if len(part) != 4 {
			continue
		}
		year := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				year = 0
				break
			}
			year = year*10 + int(r-'0')
		}
		// A sanity range rather than any four digits: an identifier can carry
		// a four-digit sequence number that is not a year, and reading one as
		// 3521 would make every release look ancient.
		if year >= 1999 && year <= 2100 {
			return year
		}
	}
	return 0
}

// NothingSince reports whether upstream has been silent since well before the
// issue was named.
//
// The reason there is no fix, reached by comparing two dates rather than by
// rating anybody's project: if the newest thing upstream has shipped long
// predates the flaw being named, then upstream has shipped nothing since it
// became known. That is arithmetic, and says nothing about whether the project
// is abandoned, busy, or disagrees that it is a flaw.
//
// **A clear year of silence, not merely an earlier year.** We have no
// disclosure date and the year in the identifier stands in for one,
// so the comparison is only as precise as a year — and comparing two
// year-numbers makes a five-week gap look identical to a five-year one. An
// issue named in January 2026 against a release the previous December is a
// project that shipped six weeks ago, and telling somebody that waiting for a
// fix is unlikely to work is a strong claim to make on that. Requiring a full
// year to have passed makes the message rarer and leaves it worth believing,
// which is the trade this already implied by saying that the gap which matters
// is measured in years.
func NothingSince(identifier string, released time.Time) bool {
	year := Identified(identifier)
	if year == 0 || released.IsZero() {
		return false
	}
	return released.UTC().Year() < year-1
}
