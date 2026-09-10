package finding

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Link is somewhere a person can read about this, worked out from what is held
// here rather than handed over by a scanner.
//
// The distinction matters and is the whole point. What a scanner points at is
// whatever its data happened to carry: for a package matched by identifier
// rather than through its own ecosystem's advisories, that is often a write-up
// belonging to a different distribution, and the issue's own record may be
// absent entirely. A name this deployment already trusts as the issue's
// identity resolves to a record without anybody having supplied a URL.
type Link struct {
	URL string
	// Name says what is at the other end, not what the address is. Somebody
	// scanning six links is choosing between kinds of source — the record, the
	// distribution's answer, the package's own page — rather than reading
	// hostnames.
	Name string
}

// Identifiers this resolves. Anchored, because a link is offered on the
// strength of the name matching a scheme and an identifier this deployment
// minted for a flaw of its own must resolve to nothing rather than to somebody
// else's page about something else.
var (
	cveName  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	ghsaName = regexp.MustCompile(`^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$`)
)

// links is everywhere this finding can be read about, in the order somebody
// works through them: the issue's own record first, then what the distribution
// says about the issue, then the package itself, then the other names the same
// issue goes by.
//
// Empty rather than approximate. A link that lands on a search page for the
// wrong thing costs more than no link, because it is followed before it is
// disbelieved.
func links(identifier string, aliases []string, purl string) []Link {
	parts := graph.PartsOfPurl(purl)

	var out []Link
	seen := map[string]bool{}
	add := func(link Link, ok bool) {
		if !ok || seen[link.URL] {
			return
		}
		seen[link.URL] = true
		out = append(out, link)
	}

	for _, link := range recordsOf(identifier) {
		add(link, true)
	}
	add(distributionAnswer(identifier, parts))
	add(packagePage(parts))
	for _, alias := range aliases {
		for _, link := range recordsOf(alias) {
			add(Link{URL: link.URL, Name: link.Name + " for " + alias}, true)
		}
	}
	return out
}

// recordsOf resolves an issue identifier to the records that define it.
//
// A CVE gets two: the record itself, which is what the identifier names, and
// the enrichment most people mean when they say "look up a CVE". They are
// different documents from different organizations and they disagree often
// enough that offering only the second would be quoting a summary as the
// source.
func recordsOf(identifier string) []Link {
	identifier = strings.TrimSpace(identifier)
	switch {
	case cveName.MatchString(identifier):
		return []Link{
			{URL: "https://www.cve.org/CVERecord?" + url.Values{"id": {identifier}}.Encode(), Name: "CVE record"},
			{URL: "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(identifier), Name: "NVD"},
		}
	case ghsaName.MatchString(identifier):
		return []Link{
			{URL: "https://github.com/advisories/" + url.PathEscape(identifier), Name: "GitHub advisory"},
		}
	}
	return nil
}

// distributionAnswer is where the distribution that packages this states what
// it has done about the issue.
//
// This is the link that answers the question a distribution's package always
// raises and that a scanner matching by identifier cannot: a backported fix
// does not move the upstream version, so "1.37.0-r31" tells nobody whether the
// patch is in it and the distribution's own tracker names the release that
// carries it.
//
// Only for a CVE, because that is the name every one of these trackers is
// keyed on.
func distributionAnswer(identifier string, parts graph.Parts) (Link, bool) {
	if !cveName.MatchString(strings.TrimSpace(identifier)) {
		return Link{}, false
	}
	switch {
	case parts.Type == "apk" && parts.Namespace == "alpine":
		return Link{
			URL:  "https://security.alpinelinux.org/vuln/" + url.PathEscape(identifier),
			Name: "Alpine security tracker",
		}, true
	case parts.Type == "deb" && parts.Namespace == "debian":
		return Link{
			URL:  "https://security-tracker.debian.org/tracker/" + url.PathEscape(identifier),
			Name: "Debian security tracker",
		}, true
	case parts.Type == "deb" && parts.Namespace == "ubuntu":
		return Link{
			URL:  "https://ubuntu.com/security/" + url.PathEscape(identifier),
			Name: "Ubuntu security",
		}, true
	case parts.Type == "rpm" && (parts.Namespace == "redhat" || parts.Namespace == "rhel"):
		return Link{
			URL:  "https://access.redhat.com/security/cve/" + url.PathEscape(strings.ToLower(identifier)),
			Name: "Red Hat security",
		}, true
	}
	return Link{}, false
}

// packagePage is where the package itself is published.
//
// Per ecosystem, because there is no general answer: an identifier says which
// kind of package it is and each kind has one place it lives. A type nothing
// here knows produces no link rather than a guess.
func packagePage(parts graph.Parts) (Link, bool) {
	name, ok := segment(parts.Name)
	if !ok {
		return Link{}, false
	}
	switch parts.Type {
	case "apk":
		// The package browser is per release branch, which the identifier
		// states as a full version — "alpine-3.24.1" is branch v3.24. Without
		// it the name still resolves, across every branch at once.
		query := url.Values{"name": {parts.Name}}
		if branch := alpineBranch(parts.Distro); branch != "" {
			query.Set("branch", branch)
		}
		return Link{URL: "https://pkgs.alpinelinux.org/packages?" + query.Encode(), Name: "Alpine package"}, true
	case "deb":
		if parts.Namespace == "ubuntu" {
			return Link{URL: "https://launchpad.net/ubuntu/+source/" + name, Name: "Ubuntu package"}, true
		}
		return Link{URL: "https://packages.debian.org/" + name, Name: "Debian package"}, true
	case "golang":
		// A module path is several segments and they are part of the name, so
		// this is the one place a separator survives escaping.
		at, ok := path(parts.Namespace, parts.Name)
		if !ok {
			return Link{}, false
		}
		if parts.Version != "" {
			version, ok := segment(parts.Version)
			if !ok {
				return Link{}, false
			}
			at += "@" + version
		}
		return Link{URL: "https://pkg.go.dev/" + at, Name: "Go module"}, true
	case "pypi":
		return Link{URL: "https://pypi.org/project/" + name + versioned("", parts.Version), Name: "PyPI project"}, true
	case "cargo":
		return Link{URL: "https://crates.io/crates/" + name + versioned("", parts.Version), Name: "Rust crate"}, true
	case "gem":
		return Link{URL: "https://rubygems.org/gems/" + name + versioned("versions", parts.Version), Name: "Ruby gem"}, true
	case "npm":
		// A scope is part of the name and is spelled with a separator.
		at, ok := path(parts.Namespace, parts.Name)
		if !ok {
			return Link{}, false
		}
		return Link{URL: "https://www.npmjs.com/package/" + at + versioned("v", parts.Version), Name: "npm package"}, true
	case "maven":
		group, ok := segment(parts.Namespace)
		if !ok {
			return Link{}, false
		}
		return Link{
			URL:  "https://central.sonatype.com/artifact/" + group + "/" + name + versioned("", parts.Version),
			Name: "Maven artifact",
		}, true
	case "github":
		owner, ok := segment(parts.Namespace)
		if !ok {
			return Link{}, false
		}
		return Link{URL: "https://github.com/" + owner + "/" + name, Name: "Source repository"}, true
	}
	return Link{}, false
}

// alpineBranch reduces the release a package was built for to the branch the
// package browser is organized by: "alpine-3.24.1" is branch "v3.24". An edge
// build states no numbers and belongs to no branch.
func alpineBranch(distro string) string {
	_, version, found := strings.Cut(strings.TrimSpace(distro), "-")
	if !found {
		return ""
	}
	segments := strings.Split(version, ".")
	if len(segments) < 2 {
		return ""
	}
	for _, segment := range segments[:2] {
		if segment == "" || strings.Trim(segment, "0123456789") != "" {
			return ""
		}
	}
	return "v" + segments[0] + "." + segments[1]
}

// segment escapes one name into one path segment.
//
// A segment of nothing but dots is refused rather than escaped. "." and ".."
// are resolved by the browser before the request is sent, so a component named
// that would quietly reach a different page on the same site — and nothing
// that is really a package is called "..". Everything else, separators
// included, is escaped into the segment it belongs to.
func segment(name string) (string, bool) {
	if name == "" || strings.Trim(name, ".") == "" {
		return "", false
	}
	return url.PathEscape(name), true
}

// path joins names that legitimately contain separators — a module path, a
// scoped package — escaping each part and refusing the whole where any part is
// one that climbs.
func path(parts ...string) (string, bool) {
	var kept []string
	for _, part := range parts {
		for _, name := range strings.Split(part, "/") {
			if name == "" {
				continue
			}
			escaped, ok := segment(name)
			if !ok {
				return "", false
			}
			kept = append(kept, escaped)
		}
	}
	if len(kept) == 0 {
		return "", false
	}
	return strings.Join(kept, "/"), true
}

// versioned is the trailing part of an address that names a version, and
// nothing at all where no version is stated or the one stated cannot be part
// of an address. The prefix is what the site puts between the package and its
// version, which differs per ecosystem and is empty for the several that put
// nothing.
func versioned(prefix, version string) string {
	escaped, ok := segment(version)
	if !ok {
		return ""
	}
	if prefix != "" {
		return "/" + prefix + "/" + escaped
	}
	return "/" + escaped
}
