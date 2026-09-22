package obligation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// knownAt is when the fixture's attack became known: a fixed moment, so what
// a window counts from is what was said rather than the moment of typing.
var knownAt = time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)

// cast is a product with an issue open in it, somebody who triages there,
// somebody who reads another product only, and an administrator.
type cast struct {
	product, issue int64
}

var castSeed = dbtest.Seed(func(ctx context.Context, db *database.DB) (cast, error) {
	cat := catalog.NewStore(db.DB)
	product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
	if err != nil {
		return cast{}, err
	}
	elsewhere, err := cat.DeclareProduct(ctx, "other", "Other")
	if err != nil {
		return cast{}, err
	}
	interned, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
		{Identifier: "CVE-2026-1", Severity: "high"},
	})
	if err != nil {
		return cast{}, err
	}
	issue := interned["CVE-2026-1"]

	stream, err := cat.DeclareStream(ctx, product.ID, "main", catalog.Branch, nil)
	if err != nil {
		return cast{}, err
	}
	variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
	if err != nil {
		return cast{}, err
	}
	target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
	if err != nil {
		return cast{}, err
	}
	run, err := finding.NewStore(db.DB).Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", RanHere: true,
	})
	if err != nil {
		return cast{}, err
	}
	now := time.Now().Truncate(time.Microsecond)
	component := &graph.Component{
		Identity: "libfoo@1.2.3", Name: "libfoo", Version: "1.2.3", FirstSeenAt: now,
	}
	if _, err := db.DB.NewInsert().Model(component).Exec(ctx); err != nil {
		return cast{}, err
	}
	if _, err := db.DB.NewInsert().Model(&finding.Finding{
		TargetID: target.ID, Kind: finding.Vulnerable, VulnerabilityID: issue,
		Visibility: access.Public, ComponentID: component.ID, PlaceIdentity: "place-of-libfoo",
		LastChangedAt: now, OpenedAt: now, OpenedRunID: &run.ID,
	}).Exec(ctx); err != nil {
		return cast{}, err
	}

	rights := access.NewStore(db.DB)
	yes := true
	if _, err := rights.Ensure(ctx, "admin", "Admin", &yes, nil); err != nil {
		return cast{}, err
	}
	triager, err := rights.Ensure(ctx, "triager", "Triager", nil, nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.GrantRole(ctx, triager.ID, product.ID, access.PublicTriage); err != nil {
		return cast{}, err
	}
	outsider, err := rights.Ensure(ctx, "outsider", "Outsider", nil, nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.GrantRole(ctx, outsider.ID, elsewhere.ID, access.PublicTriage); err != nil {
		return cast{}, err
	}
	return cast{product: product.ID, issue: issue}, nil
})

type fixture struct {
	db                       *database.DB
	store                    *obligation.Store
	product, issue           int64
	admin, triager, outsider access.Subject
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	castSeed.Each(t, func(t *testing.T, db *database.DB, c cast) {
		rights := access.NewStore(db.DB)
		subject := func(identity string) access.Subject {
			resolved, err := rights.Resolve(t.Context(), identity)
			if err != nil {
				t.Fatal(err)
			}
			return resolved
		}
		fn(t, &fixture{
			db: db, store: obligation.NewStore(db.DB), product: c.product, issue: c.issue,
			admin: subject("admin"), triager: subject("triager"), outsider: subject("outsider"),
		})
	})
}

// attacked keeps a record that the product was exploited through the issue.
func (f *fixture) attacked(t *testing.T) *triage.ExploitedHere {
	t.Helper()
	record, _, err := triage.NewStore(f.db.DB).RecordExploitedHere(t.Context(), f.triager,
		f.product, f.issue, knownAt, "A customer sent packet captures.")
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// window declares one, as the administrator.
func (f *fixture) window(t *testing.T, name string, hours int) *obligation.Window {
	t.Helper()
	declared, err := f.store.DeclareWindow(t.Context(), f.admin, name, hours)
	if err != nil {
		t.Fatal(err)
	}
	return declared
}

func TestAWindowIsDeclaredByAnAdministratorAndNobodyElse(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		_, err := f.store.DeclareWindow(t.Context(), f.triager, "Early warning", 24)
		if !errors.Is(err, access.ErrDenied) {
			t.Fatalf("a triager declaring a window answered %v", err)
		}
		f.window(t, "Early warning", 24)
	})
}

func TestAWindowOfNoLengthIsRefusedRatherThanStored(t *testing.T) {
	// Zero reads as unset everywhere, so a window of none is refused rather
	// than kept as one that closes the moment it opens.
	each(t, func(t *testing.T, f *fixture) {
		for _, hours := range []int{0, -1, obligation.LongestHours + 1} {
			if _, err := f.store.DeclareWindow(t.Context(), f.admin, "Notice", hours); err == nil {
				t.Errorf("a window of %d hours was declared", hours)
			}
		}
	})
}

func TestAWindowNameIsMatchedWithoutRegardToCapitals(t *testing.T) {
	// Two windows in force under one name would leave a notice naming either
	// ambiguous. A retired one gives its name back.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := f.window(t, "Early warning", 24)
		if _, err := f.store.DeclareWindow(ctx, f.admin, "  EARLY WARNING ", 48); !errors.Is(err,
			obligation.ErrWindowNamed) {
			t.Fatalf("a second window under the same name answered %v", err)
		}
		if err := f.store.RetireWindow(ctx, f.admin, first.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.DeclareWindow(ctx, f.admin, "early warning", 48); err != nil {
			t.Fatalf("a retired window kept its name: %v", err)
		}
	})
}

func TestAWindowRunsFromWhenTheAttackBecameKnown(t *testing.T) {
	// Not from the remediation deadline, which stops where nothing upstream
	// would close the finding — the population a flaw of our own is in — and
	// not from the moment somebody typed the record in.
	each(t, func(t *testing.T, f *fixture) {
		f.window(t, "Notification", 72)
		f.window(t, "Early warning", 24)
		f.attacked(t)

		shelf, err := f.store.Shelf(t.Context(), f.triager)
		if err != nil {
			t.Fatal(err)
		}
		if len(shelf) != 1 {
			t.Fatalf("%d incidents on the shelf, want the one", len(shelf))
		}
		due := shelf[0].Windows
		if len(due) != 2 || due[0].Window.Name != "Early warning" {
			t.Fatalf("windows are not shortest first: %+v", due)
		}
		if want := knownAt.Add(24 * time.Hour); !due[0].EndsAt.Equal(want) {
			t.Errorf("the early warning ends %s, want %s", due[0].EndsAt, want)
		}
		if want := knownAt.Add(72 * time.Hour); !due[1].EndsAt.Equal(want) {
			t.Errorf("the notification ends %s, want %s", due[1].EndsAt, want)
		}
	})
}

func TestANoticeNamingAWindowAnswersThatWindowAlone(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		early := f.window(t, "Early warning", 24)
		f.window(t, "Notification", 72)
		record := f.attacked(t)

		if _, err := f.store.RecordTold(ctx, f.triager, record.ID, &early.ID, "ENISA",
			knownAt.Add(19*time.Hour), "An attack through the management socket."); err != nil {
			t.Fatal(err)
		}
		shelf, err := f.store.Shelf(ctx, f.triager)
		if err != nil {
			t.Fatal(err)
		}
		due := shelf[0].Windows
		if !due[0].Answered {
			t.Error("the window the notice named reads as unanswered")
		}
		if due[1].Answered {
			t.Error("a window the notice did not name reads as answered")
		}
		if len(shelf[0].Told) != 1 || shelf[0].Told[0].Recipient != "ENISA" {
			t.Errorf("the notice is not on the shelf: %+v", shelf[0].Told)
		}
	})
}

func TestANoticeIsNotBeforeTheAttackBecameKnown(t *testing.T) {
	// One of the two moments is wrong, and the record is the one already
	// kept.
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		if _, err := f.store.RecordTold(t.Context(), f.triager, record.ID, nil, "ENISA",
			knownAt.Add(-time.Hour), "An attack."); err == nil {
			t.Error("a notice before the attack became known was recorded")
		}
		if _, err := f.store.RecordTold(t.Context(), f.triager, record.ID, nil, "ENISA",
			time.Now().Add(time.Hour), "An attack."); err == nil {
			t.Error("a notice still to come was recorded")
		}
	})
}

func TestANoticeIsRecordedOnlyByWhoeverMayTriageTheProduct(t *testing.T) {
	// Refused in the words a record that is not there gets, so the route is
	// not a way to walk identifiers.
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		_, err := f.store.RecordTold(t.Context(), f.outsider, record.ID, nil, "ENISA",
			knownAt.Add(time.Hour), "An attack.")
		if !errors.Is(err, obligation.ErrNoSuchRecord) {
			t.Fatalf("somebody with nothing on the product recording a notice answered %v", err)
		}
		_, err = f.store.RecordTold(t.Context(), f.outsider, record.ID+1000, nil, "ENISA",
			knownAt.Add(time.Hour), "An attack.")
		if !errors.Is(err, obligation.ErrNoSuchRecord) {
			t.Fatalf("a record nobody kept answered %v", err)
		}
	})
}

func TestTheShelfHoldsOnlyWhatTheReaderMayBeToldOf(t *testing.T) {
	// No count before the narrowing: a reader shown none is not told that
	// any exist.
	each(t, func(t *testing.T, f *fixture) {
		f.attacked(t)
		shelf, err := f.store.Shelf(t.Context(), f.outsider)
		if err != nil {
			t.Fatal(err)
		}
		if len(shelf) != 0 {
			t.Errorf("somebody with nothing on the product was shown %d incidents", len(shelf))
		}
	})
}

func TestAClearedRecordLeavesTheShelf(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		record := f.attacked(t)
		if err := triage.NewStore(f.db.DB).ClearExploitedHere(ctx, f.triager, record.ID,
			"The captures were of somebody else's deployment."); err != nil {
			t.Fatal(err)
		}
		shelf, err := f.store.Shelf(ctx, f.triager)
		if err != nil {
			t.Fatal(err)
		}
		if len(shelf) != 0 {
			t.Errorf("a cleared record is still on the shelf: %+v", shelf)
		}
	})
}
