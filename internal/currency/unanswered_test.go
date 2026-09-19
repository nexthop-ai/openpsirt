package currency_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// What the report says, and why of each.
//
// **Held back and never heard of are recorded identically**, because the pass
// must record both or starve its own window on them for ever. So the whole
// question is whether applying the list again tells them apart, and a case for
// each of the three answers is what says it does — a test with only the
// unknown arm would pass against a reader that returned that word for
// everything.
func TestWhatHasNoUpstreamAnswerSaysWhy(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		asked := time.Now().UTC().Add(-time.Hour)
		none := (*string)(nil)
		for _, purl := range []string{
			"pkg:golang/github.com/example-corp/internal-lib@v1.0.0",
			"pkg:npm/private-fork@0.1.0",
			"pkg:npm/%zz/broken@1.0.0",
			"pkg:cargo/serde@1.0.0",
			"pkg:golang/golang.org/x/net@v0.17.0",
			"pkg:deb/debian/openssl@3.5.6-1",
		} {
			put(t, w, purl, &asked, none)
		}
		// An answer we have. It is not unanswered and must not appear.
		version := "1.0.230"
		set(t, w, "pkg:cargo/serde@1.0.0", &version)
		// Never reached. Waiting is not unanswered, and reporting the first
		// day's backlog as failure would make the list useless on the day
		// somebody reads it.
		put(t, w, "pkg:pypi/requests@2.31.0", nil, none)
		carried(t, w, "",
			"pkg:golang/github.com/example-corp/internal-lib@v1.0.0",
			"pkg:npm/private-fork@0.1.0",
			"pkg:npm/%zz/broken@1.0.0",
			"pkg:cargo/serde@1.0.0",
			"pkg:golang/golang.org/x/net@v0.17.0",
			"pkg:deb/debian/openssl@3.5.6-1",
			"pkg:pypi/requests@2.31.0")

		ours := currency.Ourselves("https://example-corp.test", nil)
		rows, total, whole, err := currency.Unanswerable(
			t.Context(), w.DB.DB, everything(t, w), ours, 50, 0)
		if err != nil {
			t.Fatalf("read what has no upstream answer: %v", err)
		}
		if !whole {
			t.Error("a handful of rows was reported as past the ceiling")
		}
		want := map[string]currency.Why{
			"pkg:golang/github.com/example-corp/internal-lib@v1.0.0": currency.WhyOurs,
			"pkg:npm/private-fork@0.1.0":                             currency.WhyUnknown,
			"pkg:npm/%zz/broken@1.0.0":                               currency.WhyUnreadable,
			"pkg:golang/golang.org/x/net@v0.17.0":                    currency.WhyUnknown,
		}
		if total != len(want) {
			t.Errorf("reported %d in all, expected %d: %v", total, len(want), rows)
		}
		got := map[string]currency.Why{}
		for _, row := range rows {
			got[row.Purl] = row.Why
		}
		for purl, why := range want {
			if got[purl] != why {
				t.Errorf("%s reads as %q, expected %q", purl, got[purl], why)
			}
		}
		for purl := range got {
			if _, wanted := want[purl]; !wanted {
				t.Errorf("%s is on the list and should not be", purl)
			}
		}
	})
}

// A component in a product somebody may not read is not on their list.
//
// A package identifier says what a build is made of, so a list of them across
// the estate is an answer about products rather than about the deployment
// (REQ-42). Two products, because with one the narrowing cannot be wrong: a
// reader holding the only product reads everything whether or not the clause
// is there at all.
func TestTheReportAnswersOnlyWhatMayBeRead(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		asked := time.Now().UTC().Add(-time.Hour)
		put(t, w, "pkg:npm/here@0.1.0", &asked, nil)
		put(t, w, "pkg:npm/elsewhere@0.1.0", &asked, nil)
		carried(t, w, "", "pkg:npm/here@0.1.0")
		inAnotherProduct(t, w, "pkg:npm/elsewhere@0.1.0")

		rows, total, _, err := currency.Unanswerable(
			t.Context(), w.DB.DB, everything(t, w), currency.Ours{}, 50, 0)
		if err != nil {
			t.Fatalf("read what has no upstream answer: %v", err)
		}
		if total != 1 || len(rows) != 1 || rows[0].Purl != "pkg:npm/here@0.1.0" {
			t.Fatalf("read %d of %d, expected only the readable product's: %v",
				len(rows), total, rows)
		}
	})
}

// inAnotherProduct puts a seeded component in a build of a product the reader
// holds nothing on.
func inAnotherProduct(t *testing.T, w *fixture.World, purl string) {
	t.Helper()
	ctx := t.Context()
	other := w.DeclareProduct("other", "Another Product Entirely")
	stream := w.DeclareStream(other, "main", catalog.Branch, nil)
	variant := w.DeclareVariant(other, "only", true)
	target := w.TargetFor(stream, variant)
	scan := &ingest.Scan{
		TargetID: target.ID, ContentHash: "hash-elsewhere",
		BuiltAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
		ParserVersion: "test", Status: ingest.Accepted,
	}
	if _, err := w.DB.DB.NewInsert().Model(scan).Exec(ctx); err != nil {
		t.Fatalf("record a scan elsewhere: %v", err)
	}
	var id int64
	err := w.DB.DB.NewSelect().TableExpr(`"component" AS "c"`).
		ColumnExpr("c.id").Where("c.purl = ?", purl).Scan(ctx, &id)
	if err != nil {
		t.Fatalf("find %s: %v", purl, err)
	}
	node := &graph.Node{TargetID: target.ID, ComponentID: id, OpenedScanID: scan.ID}
	if _, err := w.DB.DB.NewInsert().Model(node).Exec(ctx); err != nil {
		t.Fatalf("put %s in another product: %v", purl, err)
	}
}

// put seeds a component with what a pass would have recorded about it.
func put(t *testing.T, w *fixture.World, purl string, checked *time.Time, version *string) {
	t.Helper()
	row := &graph.Component{
		Identity: "identity-" + purl, Purl: purl, Name: "component", Version: "1.0",
		FirstSeenAt: time.Now().UTC(), LatestCheckedAt: checked, LatestVersion: version,
	}
	if _, err := w.DB.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
		t.Fatalf("seed %s: %v", purl, err)
	}
}

// set records an answer against a component already seeded.
func set(t *testing.T, w *fixture.World, purl string, version *string) {
	t.Helper()
	_, err := w.DB.DB.NewUpdate().Table("component").
		Set("latest_version = ?", version).Where("purl = ?", purl).Exec(t.Context())
	if err != nil {
		t.Fatalf("record an answer for %s: %v", purl, err)
	}
}

// everything is somebody who may read the fixture's product, and nothing is
// somebody who may read nothing.
func everything(t *testing.T, w *fixture.World) access.Subject {
	t.Helper()
	return resolved(t, w, "reader", access.PrivateRead)
}

func resolved(t *testing.T, w *fixture.World, identity string, role access.Role) access.Subject {
	t.Helper()
	ctx := t.Context()
	who, err := w.Access.Ensure(ctx, identity, identity, nil, nil)
	if err != nil {
		t.Fatalf("record %s: %v", identity, err)
	}
	if err := w.Access.GrantRole(ctx, who.ID, w.Product.ID, role); err != nil {
		t.Fatalf("grant %s: %v", identity, err)
	}
	subject, err := w.Access.Resolve(ctx, identity)
	if err != nil {
		t.Fatalf("resolve %s: %v", identity, err)
	}
	return subject
}
