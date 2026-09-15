package finding_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAVexStatementIsStoredFoldedAndFoundOnEveryEngine(t *testing.T) {
	// Whether a publisher's judgment reaches a finding is an equality test
	// on three columns, and it used to be a LOWER() the engine performed —
	// which the four do not agree about: SQLite folds ASCII and nothing
	// else, so a component named with any letter outside it matched on
	// three engines and not on the fourth, and which one a deployment ran
	// decided whether the statement was seen. Folded on write instead, the
	// comparison is the same everywhere and the index over the three
	// columns is usable.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PrivateTriage)

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
			"Debian", "dsa.json", "sha256:one", []finding.Statement{{
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
			"debian", "dsa.json", "sha256:two", []finding.Statement{{
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
		who := f.planner(t, access.PrivateTriage)
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-1", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-1"]

		if _, _, err := f.store.RecordStatements(ctx, who, f.productID,
			"Acme", "acme.json", "sha256:one", []finding.Statement{{
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

func TestAStatementCarryingNoPackageIdentifierIsStillShown(t *testing.T) {
	// The claim against a source tree, which the name is all there is of.
	// Dropping it would silently lose every statement a publisher made the
	// only way their document could make it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PrivateTriage)
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-2", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-2"]

		if _, _, err := f.store.RecordStatements(ctx, who, f.productID,
			"Debian", "dsa.json", "sha256:two", []finding.Statement{{
				Vulnerability: "CVE-2026-2", Component: "thrift", Status: "not_affected",
			}}); err != nil {
			t.Fatal(err)
		}
		said, err := f.store.SaidAbout(ctx, who, f.productID, issue,
			[]string{"CVE-2026-2"}, "thrift", "pkg:deb/debian/thrift@0.14.1")
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 1 {
			t.Errorf("%d statements, want the one that names no identifier", len(said))
		}
	})
}
