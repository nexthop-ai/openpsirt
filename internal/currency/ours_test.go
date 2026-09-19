package currency_test

import (
	"reflect"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/currency"
)

// What a deployment's own namespace yields, and what it does not.
//
// The three spellings exist because the ecosystems spell an organization three
// ways, and a deployment states it once. A case that only checked the host
// would pass against an implementation that never derived the other two.
func TestTheNamespaceYieldsThreeSpellings(t *testing.T) {
	for _, each := range []struct {
		name      string
		namespace string
		want      []string
	}{
		{"a URL, which is what the formats require",
			"https://nexthop.ai", []string{"ai.nexthop", "nexthop", "nexthop.ai"}},
		{"a bare host, which is what several deployments write anyway",
			"nexthop.ai", []string{"ai.nexthop", "nexthop", "nexthop.ai"}},
		{"a URL with a path, which the path does not join",
			"https://example.test/psirt", []string{"example", "example.test", "test.example"}},
		{"a bare host with a path",
			"example.test/psirt", []string{"example", "example.test", "test.example"}},
		{"the web server is not the organization",
			"https://www.example.test", []string{"example", "example.test", "test.example"}},
		{"a coordination address in front of the organization yields both",
			"https://psirt.example.test",
			[]string{"example", "psirt", "psirt.example.test", "test.example.psirt"}},
		{"a generic registration label names no organization",
			"https://example.co.uk",
			[]string{"example", "example.co.uk", "uk.co.example"}},
		{"one label reverses to itself, and is not repeated",
			"http://localhost", []string{"localhost"}},
		{"a forge is nobody's organization",
			"https://example.github.io",
			[]string{"example", "example.github.io", "io.github.example"}},
		{"a name stated twice in two spellings is held once",
			"https://acme.test", []string{"acme", "acme.test", "test.acme"}},
		{"nothing configured holds nothing back", "", nil},
		{"whitespace is nothing configured", "   ", nil},
	} {
		t.Run(each.name, func(t *testing.T) {
			got := currency.Ourselves(each.namespace, nil).Labels()
			if len(got) == 0 && len(each.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, each.want) {
				t.Fatalf("%q yielded %q, wanted %q", each.namespace, got, each.want)
			}
		})
	}
}

// A deployment that has said nothing holds nothing back.
//
// The feature is a better default rather than a control, so an unconfigured
// deployment that turns asking on behaves exactly as it did before this
// existed. Pinned because the opposite mistake — guessing at who a deployment
// is — is the one that silently stops answering about real packages.
func TestNothingStatedHoldsNothingBack(t *testing.T) {
	var none currency.Ours
	if got := none.Labels(); len(got) != 0 {
		t.Fatalf("a deployment that has configured nothing holds back %q", got)
	}
	if none.HeldBack("pkg:golang/github.com/nexthop-ai/openpsirt") {
		t.Fatal("a name was held back against an empty list")
	}
}

// What a label matches, and what it stops at.
//
// **The boundary is the whole point.** Matched anywhere in the string,
// "nexthop" would hold back every package with those letters in it; matched
// only exactly, it would miss the organization's own family of names, which is
// most of what it exists for.
func TestALabelMatchesAtSeparators(t *testing.T) {
	ours := currency.Ourselves("https://nexthop.ai", nil)
	for _, each := range []struct {
		name string
		purl string
		want bool
	}{
		{"the organization itself, as a forge account",
			"pkg:golang/github.com/nexthop/thing", true},
		{"the account with a suffix, which is the ordinary shape",
			"pkg:golang/github.com/nexthop-ai/openpsirt", true},
		{"a scope, whose @ is punctuation rather than part of the name",
			"pkg:npm/%40nexthop/agent", true},
		{"a scope written unescaped",
			"pkg:npm/@nexthop/agent", true},
		{"a bare package named after the organization",
			"pkg:pypi/nexthop-tools", true},
		{"a group in reverse, which is how Java spells it",
			"pkg:maven/ai.nexthop/lib", true},
		{"a longer group under that one",
			"pkg:maven/ai.nexthop.internal/lib", true},
		{"the host as a module path segment",
			"pkg:golang/nexthop.ai/sdk", true},
		{"the last segment counts too, because not every package has a scope",
			"pkg:cargo/nexthop", true},
		{"a different organization whose name begins the same way",
			"pkg:npm/nexthopper", false},
		{"the letters in the middle of somebody else's name",
			"pkg:npm/phone-nexthop-client", false},
		{"a forge everybody shares is not ours",
			"pkg:golang/github.com/someone/else", false},
		{"an ordinary dependency",
			"pkg:npm/lodash", false},
		{"a distribution package, which is never asked about anyway",
			"pkg:deb/debian/nexthop-ai", true},
		{"an identifier nothing can read is not held back, it is unreadable",
			"not-a-purl", false},
		{"the case it is written in does not decide",
			"pkg:golang/github.com/NextHop-AI/Thing", true},
		// A vanity import path and a self-hosted forge both put the
		// organization's host in front of the package, and a label matched
		// only where it begins a segment covers neither.
		{"a module under a subdomain of our own host",
			"pkg:golang/go.nexthop.ai/team/agent", true},
		{"a host that merely ends the same way is somebody else",
			"pkg:golang/notnexthop.ai/thing", false},
	} {
		t.Run(each.name, func(t *testing.T) {
			if got := ours.HeldBack(each.purl); got != each.want {
				t.Fatalf("%q held back: %v, wanted %v", each.purl, got, each.want)
			}
		})
	}
}

// What the deployment stated is held back beside what was derived.
func TestWhatTheDeploymentStatedIsHeldBackToo(t *testing.T) {
	ours := currency.Ourselves("", []string{"skunkworks", "  ", "Acme-Internal"})
	if !ours.HeldBack("pkg:npm/skunkworks-ui") {
		t.Fatal("a stated name was not held back")
	}
	if !ours.HeldBack("pkg:golang/github.com/acme-internal/tooling") {
		t.Fatal("a stated name was not matched in the case it was written in")
	}
	if ours.HeldBack("pkg:npm/lodash") {
		t.Fatal("an ordinary dependency was held back")
	}
	if got := ours.Labels(); !reflect.DeepEqual(got, []string{"acme-internal", "skunkworks"}) {
		t.Fatalf("the labels read back as %q", got)
	}
	// Stated twice in two spellings, which reached the report twice: the
	// duplicate check searched a slice the loop had not sorted yet.
	twice := currency.Ourselves("", []string{"Widgets", "acme", "ACME", "widgets"})
	if got := twice.Labels(); !reflect.DeepEqual(got, []string{"acme", "widgets"}) {
		t.Fatalf("a name stated twice reads back as %q", got)
	}
}

// Who publishes a root, which is the part of it that is ours by construction.
//
// **The segment beside the name, never the whole namespace.** Taking the whole
// of it would hold back every package on a shared forge while reporting that
// it was protecting one organization, which is the failure that would make an
// operator turn the feature off rather than tune it.
func TestTheOwnerIsTheSegmentBesideTheName(t *testing.T) {
	for _, each := range []struct {
		name string
		purl string
		want string
	}{
		{"a module path, whose forge host is shared by everybody",
			"pkg:golang/github.com/nexthop-ai/openpsirt@v1.2.3", "nexthop-ai"},
		{"a scope",
			"pkg:npm/%40nexthop/agent@1.0.0", "nexthop"},
		{"a group, which is one segment however many dots it carries",
			"pkg:maven/ai.nexthop/lib@2.0", "ai.nexthop"},
		{"an image, which carries no namespace at all",
			"pkg:oci/openpsirt@sha256:abc", ""},
		{"a bare package",
			"pkg:pypi/requests", ""},
		{"an identifier nothing can read",
			"openpsirt-1.0.tar.gz", ""},
	} {
		t.Run(each.name, func(t *testing.T) {
			if got := currency.Owner(each.purl); got != each.want {
				t.Fatalf("%q is published by %q, wanted %q", each.purl, got, each.want)
			}
		})
	}
}

// A root folded in holds back what is published beside it, and the derived
// list says so.
func TestARootIsFoldedIn(t *testing.T) {
	ours := currency.Ourselves("", nil).
		With("pkg:golang/github.com/nexthop-ai/openpsirt@v1", "pkg:oci/image@sha256:abc")
	if !ours.HeldBack("pkg:golang/github.com/nexthop-ai/some-internal-module") {
		t.Fatal("a module published beside the root was not held back")
	}
	if ours.HeldBack("pkg:npm/image-tools") {
		t.Fatal("a root carrying no namespace held something back anyway")
	}
	if got := ours.Labels(); !reflect.DeepEqual(got, []string{"nexthop-ai"}) {
		t.Fatalf("the labels read back as %q", got)
	}
}

// Folding a root in leaves the value it was folded into alone.
//
// The pass derives one per cycle from the roots of the moment. Written as a
// mutation, a product declared in one cycle would stay held back in every
// later one whether or not it was still there, and nothing would say so.
func TestFoldingARootInDoesNotChangeWhatItCameFrom(t *testing.T) {
	ours := currency.Ourselves("https://example.test", nil)
	before := ours.Labels()
	ours.With("pkg:golang/github.com/somebody/thing")
	if got := ours.Labels(); !reflect.DeepEqual(got, before) {
		t.Fatalf("folding a root in changed the original to %q, from %q", got, before)
	}
}
