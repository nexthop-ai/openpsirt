// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// versionMark stands where a name held its own version. A name stored is
// printable, so no name holds it, and a name with its version taken out never
// equals a name that held none. It is not the null character, which joins a
// consumer's name to a component's in an occurrence identity.
const versionMark = "\x01"

// IdentifyingName is the name a component is continued under from one version
// to the next: its name with every place it states its own release taken out.
//
// A distribution that names a package after its version renames it on every
// upgrade, so a name read as given makes each upgrade a different package and
// discards what was decided about it. Debian's kernel is
// `linux-image-6.12.41+deb13-sonic-amd64-unsigned` at `6.12.41-1`, and
// `linux-image-6.12.94+deb13-sonic-amd64-unsigned` once it moves.
//
// The release is the version without what the ecosystem's distribution adds,
// as vercmp.Release reads it for the type the package identifier names. It is
// taken out only as a whole token, with no letter or digit on either side, so
// `libssl3` at `3.5.1` and `python3.11` at `3.11.2` keep their names: those
// carry an interface number, never their version. A name that is its version
// and nothing more keeps it, since nothing else would be left to tell two such
// packages apart.
func IdentifyingName(name, version, purl string) string {
	name = strings.TrimSpace(name)
	release := vercmp.Release(vercmp.SchemeOf(EcosystemOf(purl)), version)
	if release == "" || release == name || !strings.Contains(name, release) {
		return name
	}
	var out strings.Builder
	written, from := 0, 0
	for {
		at := strings.Index(name[from:], release)
		if at < 0 {
			break
		}
		at += from
		end := at + len(release)
		if !bounded(name[:at], name[end:]) {
			// Not a token: look again one character on, so a release starting
			// inside this match is still found.
			_, width := utf8.DecodeRuneInString(name[at:])
			from = at + width
			continue
		}
		out.WriteString(name[written:at])
		out.WriteString(versionMark)
		written, from = end, end
	}
	if written == 0 {
		return name
	}
	out.WriteString(name[written:])
	return out.String()
}

// IdentifyingExpr is the identifying name of the component aliased alias,
// folded, as a statement reads it: the stored column where the name holds its
// own version, and the folded name where it holds none.
func IdentifyingExpr(alias string) string {
	return `COALESCE("` + alias + `"."identifying_folded", "` + alias + `"."name_folded")`
}

// StoredIdentifying is what a component row stores as its identifying
// name folded: empty where the name holds no version of its own.
func StoredIdentifying(name, version, purl string) string {
	identifying := IdentifyingName(name, version, purl)
	if identifying == strings.TrimSpace(name) {
		return ""
	}
	return Folded(identifying)
}

// IdentifyingName is the component's name as IdentifyingName reads it, from
// its row's name, version and package identifier.
func (c Component) IdentifyingName() string {
	return IdentifyingName(c.Name, c.Version, c.Purl)
}

// bounded is whether text between before and after stands as a token: no
// letter or digit runs into it from either side, and no dot carries a longer
// number on, since `libsaibcm_dnx_15.2.0.0.0.0.16.2_amd64.deb` at `0.0.0` holds
// a placeholder inside another version.
func bounded(before, after string) bool {
	if last, _ := utf8.DecodeLastRuneInString(before); before != "" && alphanumeric(last) {
		return false
	}
	if first, _ := utf8.DecodeRuneInString(after); after != "" && alphanumeric(first) {
		return false
	}
	if trimmed, dot := strings.CutSuffix(before, "."); dot {
		if last, _ := utf8.DecodeLastRuneInString(trimmed); trimmed != "" && unicode.IsDigit(last) {
			return false
		}
	}
	if trimmed, dot := strings.CutPrefix(after, "."); dot {
		if first, _ := utf8.DecodeRuneInString(trimmed); trimmed != "" && unicode.IsDigit(first) {
			return false
		}
	}
	return true
}

// alphanumeric is whether a character is a letter or a digit.
func alphanumeric(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
