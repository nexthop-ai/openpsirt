// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAVexStatementIsStoredFoldedAndFoundOnEveryEngine(t *testing.T) {
	// A publisher's judgment reaching a finding is an equality test on three
	// columns. Spelled as a LOWER() the engine performs, the four do not
	// agree: SQLite folds ASCII and nothing else, so a component named with
	// any letter outside it matches on three engines and not on the fourth,
	// and which one a deployment runs decided whether the statement was seen.
	// Folded on write instead, the comparison is the same everywhere and the
	// index over the three columns is usable.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)

		// The issue the statements are about. Asked for by identifier here
		// and matched by name in the query, because which name a publisher
		// used is theirs to choose — but who may be told about it is a
		// question about the issue, so the read takes its identifier.
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-1", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-1"]

		// A name with a letter outside ASCII, in capitals. This is the case
		// the two folds disagree about.
		const component = "libFÜNF"
		recorded, superseded, err2 := f.store.RecordStatements(ctx, who, f.productID,
			finding.Supplied{Source: finding.FromVex, Publisher: "Debian",
				Document: "dsa.json", Digest: "sha256:one"}, []finding.Statement{{
				Vulnerability: "CVE-2026-1", Component: component,
				Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
				Statement: "The affected function is never reached in our build.",
			}})
		if err2 != nil {
			t.Fatal(err2)
		}
		if recorded != 1 || superseded != 0 {
			t.Fatalf("recording one statement reports %d recorded and %d set aside",
				recorded, superseded)
		}

		// Found however the asker spells it, on every engine.
		for _, spelling := range []string{component, strings.ToLower(component), "LIBFÜNF"} {
			said, err := f.store.SaidAbout(ctx, who, f.productID, issue,
				[]string{"cve-2026-1", "CVE-2026-1"}, spelling, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(said) != 1 {
				t.Errorf("asking about %q found %d statements, want the one",
					spelling, len(said))
			}
		}

		// A second document from the same publisher sets aside the first
		// rather than sitting beside it: what a publisher says now is what
		// they say, and "they changed their mind" is a fact the record keeps.
		_, setAside, err := f.store.RecordStatements(ctx, who, f.productID,
			finding.Supplied{Source: finding.FromVex, Publisher: "debian",
				Document: "dsa.json", Digest: "sha256:two"}, []finding.Statement{{
				Vulnerability: "CVE-2026-1", Component: component,
				Status: "affected", Statement: "On reflection, it is reachable.",
			}})
		if err != nil {
			t.Fatal(err)
		}
		if setAside != 1 {
			t.Errorf("a second document set aside %d of the first's statements", setAside)
		}
		said, err := f.store.SaidAbout(ctx, who, f.productID, issue,
			[]string{"CVE-2026-1"}, component, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 1 || said[0].Status != "affected" {
			t.Errorf("what stands is %+v, want only the newer statement", said)
		}

		// And a product the asker cannot see answers with a refusal rather
		// than with somebody else's VEX evidence.
		stranger := f.planner(t)
		if _, err := f.store.SaidAbout(ctx, stranger, f.productID+9999, issue,
			[]string{"CVE-2026-1"}, component, ""); err == nil {
			t.Error("a product nobody holds anything on answered with statements")
		}
	})
}

func TestAStatementAboutOnePackageIsNotShownAgainstAnotherOfTheSameName(t *testing.T) {
	// A component in the graph is called by its short name, so a statement is
	// stored and matched under that — and a short name is not a package. Two
	// registries and two namespaces hold different packages under one, so a
	// publisher's statement about a scoped npm package was shown against
	// every component called `parser`, from anywhere, with that publisher's
	// name on it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-1", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-1"]

		if _, _, err := f.store.RecordStatements(ctx, who, f.productID,
			finding.Supplied{Source: finding.FromVex, Publisher: "Acme",
				Document: "acme.json", Digest: "sha256:one"}, []finding.Statement{{
				Vulnerability: "CVE-2026-1", Component: "parser",
				Purl:   "pkg:npm/@acme/parser@1.0.0",
				Status: "not_affected",
			}}); err != nil {
			t.Fatal(err)
		}

		for _, c := range []struct {
			what string
			purl string
			want int
		}{
			{"the package the statement names", "pkg:npm/%40acme/parser@1.2.0", 1},
			{"an unrelated package of the same short name", "pkg:npm/parser@1.2.0", 0},
			{"the same short name in another namespace", "pkg:npm/%40other/parser@1.2.0", 0},
			{"the same short name in another registry", "pkg:pypi/parser@1.2.0", 0},
			// A component the inventory named without an identifier: there is
			// nothing to compare, and the name is all there is.
			{"a component that carries no identifier", "", 1},
		} {
			said, err := f.store.SaidAbout(ctx, who, f.productID, issue,
				[]string{"CVE-2026-1"}, "parser", c.purl)
			if err != nil {
				t.Fatal(err)
			}
			if len(said) != c.want {
				t.Errorf("%s: %d statements, want %d", c.what, len(said), c.want)
			}
		}
	})
}

func TestASourceTreeClaimIsShownHoweverItWasNamed(t *testing.T) {
	// The claim against a source tree, which the name is all there is of.
	// Dropping it would silently lose every statement a publisher made the
	// only way their document could make it.
	//
	// A source tree is named either way it can be named: as a bare name, and
	// as a package identifier of the generic type. The matching rules treat
	// the two as one claim. Narrowing the second away here compares a source
	// tree's type against the component's own, so a statement that already
	// suppressed the finding is missing from the evidence for it and the page
	// says nobody has spoken.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-2", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-2"]

		if _, _, err := f.store.RecordStatements(ctx, who, f.productID,
			finding.Supplied{Source: finding.FromVex, Publisher: "Debian",
				Document: "dsa.json", Digest: "sha256:two"}, []finding.Statement{{
				Vulnerability: "CVE-2026-2", Component: "thrift", Status: "not_affected",
			}}); err != nil {
			t.Fatal(err)
		}
		// The same claim from another publisher, spelled as an identifier.
		// Another publisher because a second document from the first sets
		// the first aside, which is a different rule.
		if _, _, err := f.store.RecordStatements(ctx, who, f.productID,
			finding.Supplied{Source: finding.FromVex, Publisher: "Apache",
				Document: "apache.json", Digest: "sha256:three"}, []finding.Statement{{
				Vulnerability: "CVE-2026-2", Component: "thrift",
				Purl:   "pkg:generic/thrift@0.14.1",
				Status: "not_affected",
			}}); err != nil {
			t.Fatal(err)
		}
		said, err := f.store.SaidAbout(ctx, who, f.productID, issue,
			[]string{"CVE-2026-2"}, "thrift", "pkg:deb/debian/thrift@0.14.1")
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 2 {
			t.Errorf("%d statements, want the source tree named both ways", len(said))
		}
	})
}

func TestOneAdvisoryReplacesItselfAndNothingElseThePublisherIssued(t *testing.T) {
	// A publisher's statement set is their whole answer and is replaced as
	// one. An advisory is one announcement among hundreds, so keyed on the
	// publisher alone every advisory of theirs on record would be set aside
	// the moment the next one arrived — and the deployment would hold exactly
	// the last document anybody uploaded.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{
				{Identifier: "CVE-2026-1", Severity: "high"},
				{Identifier: "CVE-2026-2", Severity: "high"},
			})
		if err != nil {
			t.Fatal(err)
		}

		first := finding.Supplied{
			Source: finding.FromAdvisory, Identifier: "EXSA-2026:1",
			Publisher: "Example", Document: "one.json", Digest: "sha256:one",
		}
		second := finding.Supplied{
			Source: finding.FromAdvisory, Identifier: "EXSA-2026:2",
			Publisher: "Example", Document: "two.json", Digest: "sha256:two",
		}
		if _, _, err := f.store.RecordStatements(ctx, who, f.productID, first,
			[]finding.Statement{{
				Vulnerability: "CVE-2026-1", Component: "libnl", Status: "fixed",
			}}); err != nil {
			t.Fatal(err)
		}
		// A second advisory from the same publisher sets nothing aside.
		_, setAside, err := f.store.RecordStatements(ctx, who, f.productID, second,
			[]finding.Statement{{
				Vulnerability: "CVE-2026-2", Component: "zlib", Status: "fixed",
			}})
		if err != nil {
			t.Fatal(err)
		}
		if setAside != 0 {
			t.Errorf("a second advisory set aside %d claims of the first", setAside)
		}
		still, err := f.store.SaidAbout(ctx, who, f.productID, interned["CVE-2026-1"],
			[]string{"CVE-2026-1"}, "libnl", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(still) != 1 {
			t.Fatalf("the first advisory left %d standing claims", len(still))
		}

		// A revision of the first replaces the first and leaves the second.
		revised := first
		revised.Digest = "sha256:revised"
		_, replaced, err := f.store.RecordStatements(ctx, who, f.productID, revised,
			[]finding.Statement{{
				Vulnerability: "CVE-2026-1", Component: "libnl", Status: "not_affected",
			}})
		if err != nil {
			t.Fatal(err)
		}
		if replaced != 1 {
			t.Errorf("a revision of one advisory set aside %d claims, want its own one",
				replaced)
		}
		other, err := f.store.SaidAbout(ctx, who, f.productID, interned["CVE-2026-2"],
			[]string{"CVE-2026-2"}, "zlib", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(other) != 1 {
			t.Errorf("revising one advisory left %d of the other standing", len(other))
		}
	})
}

func TestAStatementSetAndAnAdvisoryDoNotReplaceEachOther(t *testing.T) {
	// One publisher issues both. Swept on the publisher alone, uploading their
	// statement set sets aside every advisory of theirs on record, and each
	// advisory sets aside the statement set.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-1", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.RecordStatements(ctx, who, f.productID,
			finding.Supplied{
				Source: finding.FromAdvisory, Identifier: "EXSA-2026:1",
				Publisher: "Example", Document: "advisory.json", Digest: "sha256:one",
			}, []finding.Statement{{
				Vulnerability: "CVE-2026-1", Component: "libnl", Status: "fixed",
			}}); err != nil {
			t.Fatal(err)
		}
		_, setAside, err := f.store.RecordStatements(ctx, who, f.productID,
			finding.Supplied{
				Source: finding.FromVex, Publisher: "Example",
				Document: "vex.json", Digest: "sha256:two",
			}, []finding.Statement{{
				Vulnerability: "CVE-2026-1", Component: "zlib", Status: "not_affected",
			}})
		if err != nil {
			t.Fatal(err)
		}
		if setAside != 0 {
			t.Errorf("a statement set put aside %d claims from an advisory", setAside)
		}
		said, err := f.store.SaidAbout(ctx, who, f.productID, interned["CVE-2026-1"],
			[]string{"CVE-2026-1"}, "libnl", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 1 {
			t.Fatalf("the advisory's claim stands %d times", len(said))
		}
		if said[0].Source != finding.FromAdvisory || said[0].Identifier != "EXSA-2026:1" {
			t.Errorf("what came back is %+v, and where it came from is how a reader "+
				"places it", said[0])
		}
	})
}

func TestAnAdvisoryWithNoNameOfItsOwnIsRefusedByTheStore(t *testing.T) {
	// Refused here as well as at the endpoint, because this is reachable from
	// any other caller and what it refuses is a key collapsing into somebody
	// else's.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		for _, each := range []struct {
			what string
			from finding.Supplied
		}{
			{"an advisory carrying no name", finding.Supplied{
				Source: finding.FromAdvisory, Publisher: "Example"}},
			{"a statement set carrying one", finding.Supplied{
				Source: finding.FromVex, Identifier: "EXSA-2026:1", Publisher: "Example"}},
			{"a document of no kind", finding.Supplied{Publisher: "Example"}},
			{"a document naming nobody", finding.Supplied{Source: finding.FromVex}},
		} {
			if _, _, err := f.store.RecordStatements(ctx, who, f.productID, each.from,
				nil); err == nil {
				t.Errorf("%s was recorded", each.what)
			}
		}
	})
}

func TestAClaimAboutOneVersionOffersNothingAtAnother(t *testing.T) {
	// A publisher saying a vulnerability is fixed in one version is saying
	// nothing about another. Offered anyway, the control comes prefilled with
	// a claim they never made and their name is on it.
	// The version is a field the store carries, not something read back out
	// of the identifier: a publisher that states products and no identifier
	// at all still names a version, and there would be nothing to read it
	// out of.
	fixed := finding.Statement{
		Status: "fixed", Purl: "pkg:rpm/example/libnl@3.7.0-1.el9?arch=x86_64",
		About: "3.7.0-1.el9",
	}
	if _, offers := fixed.PrefillsFor("3.7.0-1.el9"); !offers {
		t.Error("a claim about the version shipped here offered nothing")
	}
	if outcome, offers := fixed.PrefillsFor("3.6.0-1.el9"); offers {
		t.Errorf("a claim about another version offered %q", outcome)
	}
	// A claim naming no version is about whatever is shipped, which is how a
	// publisher states something about a family.
	family := finding.Statement{Status: "not_affected", Purl: "pkg:rpm/example/libnl"}
	named := finding.Statement{Status: "affected", Component: "wt676", About: "3.94"}
	if _, offers := named.PrefillsFor("3.94"); !offers {
		t.Error("a claim naming no package missed the version it was made about")
	}
	if outcome, offers := named.PrefillsFor("4.10"); offers {
		t.Errorf("a claim about 3.94 offered %q at 4.10", outcome)
	}
	if _, offers := family.PrefillsFor("3.6.0-1.el9"); !offers {
		t.Error("a claim naming no version offered nothing")
	}
	bare := finding.Statement{Status: "affected"}
	if _, offers := bare.PrefillsFor("3.6.0-1.el9"); !offers {
		t.Error("a claim made against a source tree offered nothing")
	}
	// Under investigation still offers nothing, at any version.
	looking := finding.Statement{Status: "under_investigation"}
	if _, offers := looking.PrefillsFor("3.6.0-1.el9"); offers {
		t.Error("a publisher saying they do not know yet offered an outcome")
	}
}

func TestRecordingTheSameClaimsAgainStatesNoKeyItWasGiven(t *testing.T) {
	// The closure a transaction runs is re-run whole when the transaction is
	// retried, over the same claims. The engine writes the key it assigned
	// back into the value it inserted, so a second pass that states those keys
	// is a write that cannot happen twice — and the write a retry exists to
	// repeat is exactly that one.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		claims := []finding.Statement{{
			Vulnerability: "CVE-2026-1", Component: "libnl", Status: "fixed",
		}, {
			Vulnerability: "CVE-2026-2", Component: "zlib", Status: "not_affected",
		}}
		from := finding.Supplied{
			Source: finding.FromAdvisory, Identifier: "EXSA-2026:1",
			Publisher: "Example", Document: "one.json", Digest: "sha256:one",
		}
		if _, _, err := f.store.RecordStatements(ctx, who, f.productID, from,
			claims); err != nil {
			t.Fatal(err)
		}
		// The same slice, the way a retry hands it back.
		recorded, _, err := f.store.RecordStatements(ctx, who, f.productID, from, claims)
		if err != nil {
			t.Fatalf("recording the same claims again: %v", err)
		}
		if recorded != len(claims) {
			t.Errorf("the second pass recorded %d of %d", recorded, len(claims))
		}
	})
}
