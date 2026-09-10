package notify_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

func TestSomebodyJustAddedIsNotAlreadyAbsent(t *testing.T) {
	// The threshold runs from when somebody was added where they have never
	// signed in. Compared against the moment alone, an administrator adding a
	// colleague and assigning them something raises an alert about them in the
	// same breath — which is what happened, and an existing test caught it.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hush := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, hush); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", true)
		if err != nil {
			t.Fatal(err)
		}
		// Added a moment ago, has never signed in, and holding something.
		fresh, err := rights.Ensure(ctx, "fresh@example.com", "Fresh Start", false)
		if err != nil {
			t.Fatal(err)
		}
		assignOne(t, db, fresh.ID)

		if _, _, err := notify.NewWatch(db.DB, hush).Once(ctx); err != nil {
			t.Fatal(err)
		}
		items, _, err := notify.NewStore(db.DB).Waiting(ctx,
			access.NewPerson(admin.ID, admin.Identity, true, nil, 0), 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			if item.Kind == notify.HoldingAbsent {
				t.Errorf("somebody added a moment ago was raised as absent: %q", item.Body)
			}
		}
	})
}

// assignOne records one open finding held by somebody, which is the least that
// makes them a person holding work.
func assignOne(t *testing.T, db *database.DB, holder int64) {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(db.DB)
	product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
	if err != nil {
		t.Fatal(err)
	}
	branch, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
	if err != nil {
		t.Fatal(err)
	}
	variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
	if err != nil {
		t.Fatal(err)
	}
	target, err := cat.TargetFor(ctx, branch.ID, variant.ID)
	if err != nil {
		t.Fatal(err)
	}
	named, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
		{Identifier: "CVE-2026-1", Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	component := &graph.Component{
		Identity: "c1", Name: "libnl-3-200", Version: "3.7.0",
		Purl: "pkg:deb/debian/libnl@3.7.0",
	}
	if _, err := db.DB.NewInsert().Model(component).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range named {
		row := &finding.Finding{
			TargetID: target.ID, Kind: "dependency", VulnerabilityID: id,
			Visibility: access.Public, ComponentID: component.ID,
			PlaceIdentity: "place-1", Urgency: 1,
			OpenedAt: time.Now().UTC(), AssignedTo: &holder,
		}
		if _, err := db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSomebodyAwayHoldingWorkIsRaisedAndAnIdleAccountIsNot(t *testing.T) {
	// and both halves of it. An account nobody has used in a month is
	// harmless if it holds nothing; work stuck behind somebody who is not
	// here is the problem, and this is the prompt that makes an
	// administrator realize they have gone.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hush := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, hush); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", true)
		if err != nil {
			t.Fatal(err)
		}
		away, err := rights.Ensure(ctx, "away@example.com", "Ana Away", false)
		if err != nil {
			t.Fatal(err)
		}
		// Away just as long, and holding nothing. An idle account is not an
		// alert; it is an account.
		idle, err := rights.Ensure(ctx, "idle@example.com", "Ivan Idle", false)
		if err != nil {
			t.Fatal(err)
		}
		// Here yesterday and holding work, which is somebody doing their job.
		here, err := rights.Ensure(ctx, "here@example.com", "Hana Here", false)
		if err != nil {
			t.Fatal(err)
		}

		long := time.Now().UTC().Add(-30 * 24 * time.Hour)
		recent := time.Now().UTC().Add(-24 * time.Hour)
		for who, seen := range map[int64]time.Time{
			away.ID: long, idle.ID: long, here.ID: recent, admin.ID: recent,
		} {
			if _, err := db.DB.NewUpdate().Table("person").
				Set("last_seen_at = ?", seen).Where("id = ?", who).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		// A build with two findings, one held by each of the two who hold any.
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		branch, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, branch.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		issues := finding.NewVulnerabilities(db.DB)
		named, err := issues.Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-1", Severity: "high"},
			{Identifier: "CVE-2026-2", Severity: "high"},
		})
		if err != nil {
			t.Fatal(err)
		}
		component := &graph.Component{
			Identity: "c1", Name: "libnl-3-200", Version: "3.7.0",
			Purl: "pkg:deb/debian/libnl@3.7.0",
		}
		if _, err := db.DB.NewInsert().Model(component).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		holder := map[string]int64{"CVE-2026-1": away.ID, "CVE-2026-2": here.ID}
		for identifier, id := range named {
			held := holder[identifier]
			row := &finding.Finding{
				TargetID: target.ID, Kind: "dependency", VulnerabilityID: id,
				Visibility: access.Public, ComponentID: component.ID,
				PlaceIdentity: "place-" + identifier, Urgency: 1,
				OpenedAt: time.Now().UTC(), AssignedTo: &held,
			}
			if _, err := db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		watch := notify.NewWatch(db.DB, hush)
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}

		items, _, err := notify.NewStore(db.DB).Waiting(ctx,
			access.NewPerson(admin.ID, admin.Identity, true, nil, 0), 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var said []string
		for _, item := range items {
			if item.Kind == notify.HoldingAbsent {
				said = append(said, item.Body)
			}
		}
		if len(said) != 1 {
			t.Fatalf("raised %d absences, want the one person away and holding work: %v", len(said), said)
		}
		// The sentence the decision asks for: who, how long, and how much.
		for _, want := range []string{"Ana Away", "days", "1 item"} {
			if !contains(said[0], want) {
				t.Errorf("the alert does not say %q: %q", want, said[0])
			}
		}

		// Running it again says the same thing, so nothing opens twice.
		if opened, _, err := watch.Once(ctx); err != nil || opened != 0 {
			t.Errorf("a second sweep opened %d (err %v), want nothing", opened, err)
		}

		// They come back, and the condition clears itself — nobody dismisses
		// it, which is what makes these conditions rather than events.
		if _, err := db.DB.NewUpdate().Table("person").
			Set("last_seen_at = ?", time.Now().UTC()).
			Where("id = ?", away.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, cleared, err := watch.Once(ctx); err != nil || cleared != 1 {
			t.Errorf("after they signed in: cleared %d (err %v), want 1", cleared, err)
		}
	})
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
