// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// knownAt is when the fixture's attack became known: a fixed moment, so what
// a window counts from is what was said rather than the moment of typing.
var knownAt = time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)

// cast is a product with an issue open in it, somebody who triages its public
// findings, somebody who triages its undisclosed ones too, somebody who reads
// another product only, and an administrator.
type cast struct {
	product, issue int64
}

var castSeed = dbtest.Seed(func(ctx context.Context, db *database.DB) (cast, error) {
	w, err := world.Declare(ctx, db)
	if err != nil {
		return cast{}, err
	}
	product, target := w.Product, w.Target
	elsewhere, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "other", "Other")
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
	insider, err := rights.Ensure(ctx, "insider", "Insider", nil, nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.GrantRole(ctx, insider.ID, product.ID, access.PrivateTriage); err != nil {
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
	db                                *database.DB
	store                             *obligation.Store
	product, issue                    int64
	admin, triager, insider, outsider access.Subject
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
			admin: subject("admin"), triager: subject("triager"), insider: subject("insider"),
			outsider: subject("outsider"),
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
	declared, err := f.store.DeclareWindow(t.Context(), f.admin, obligation.WindowSaid{Name: name, Hours: hours})
	if err != nil {
		t.Fatal(err)
	}
	return declared
}

func TestAWindowIsDeclaredByAnAdministratorAndNobodyElse(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		_, err := f.store.DeclareWindow(t.Context(), f.triager, obligation.WindowSaid{Name: "Early warning", Hours: 24})
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
			if _, err := f.store.DeclareWindow(t.Context(), f.admin, obligation.WindowSaid{Name: "Notice", Hours: hours}); err == nil {
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
		if _, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{Name: "  EARLY WARNING ", Hours: 48}); !errors.Is(err,
			obligation.ErrWindowNamed) {
			t.Fatalf("a second window under the same name answered %v", err)
		}
		if err := f.store.RetireWindow(ctx, f.admin, first.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{Name: "early warning", Hours: 48}); err != nil {
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
			knownAt.Add(19*time.Hour), "An attack through the management socket.", obligation.Details{}); err != nil {
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

func TestAWindowIsReadNarrowedToTheProductsTheReaderMayKnow(t *testing.T) {
	// The list of products is a statement about what an organization ships,
	// so a window limited to products the reader may not know exist is left
	// out, and the products a window names are narrowed to the ones they may.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		hidden, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Sonic only", Hours: 24, Products: []string{world.ProductName},
		})
		if err != nil {
			t.Fatal(err)
		}
		both, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Both", Hours: 48, Products: []string{world.ProductName, "other"},
		})
		if err != nil {
			t.Fatal(err)
		}
		everywhere := f.window(t, "Everywhere", 72)

		read, err := f.store.Windows(ctx, f.outsider)
		if err != nil {
			t.Fatal(err)
		}
		held := map[int64][]string{}
		for _, window := range read {
			held[window.ID] = window.ProductNames
		}
		if _, ok := held[hidden.ID]; ok {
			t.Error("a window limited to a product the reader may not know was read")
		}
		if names, ok := held[both.ID]; !ok || len(names) != 1 || names[0] != "other" {
			t.Errorf("a window over two products reads as limited to %v, want [other]", names)
		}
		if names, ok := held[everywhere.ID]; !ok || len(names) != 0 {
			t.Errorf("a window over every product reads as %v (listed: %v)", names, ok)
		}

		// The deployment's own pass reads every window whole.
		all, err := f.store.Windows(ctx, access.Everything("the obligation sweep"))
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 3 {
			t.Errorf("the pass read %d windows, want all 3", len(all))
		}
	})
}

func TestANoticeNamesOnlyAWindowThatAppliesToItsProduct(t *testing.T) {
	// A window limited to other products is not one this record answers, and
	// its name is not the triager's to learn: it is refused as a window
	// nobody declared.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		elsewhere, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Other's window", Hours: 24, Products: []string{"other"},
		})
		if err != nil {
			t.Fatal(err)
		}
		here, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Sonic's window", Hours: 24, Products: []string{world.ProductName},
		})
		if err != nil {
			t.Fatal(err)
		}
		record := f.attacked(t)
		if _, err := f.store.RecordTold(ctx, f.triager, record.ID, &elsewhere.ID, "ENISA",
			knownAt.Add(time.Hour), "Told.", obligation.Details{}); !errors.Is(err, obligation.ErrNoSuchWindow) {
			t.Errorf("a notice naming a window limited to another product answered %v", err)
		}
		if _, err := f.store.RecordTold(ctx, f.triager, record.ID, &here.ID, "ENISA",
			knownAt.Add(time.Hour), "Told.", obligation.Details{}); err != nil {
			t.Fatalf("a notice naming a window limited to its own product answered %v", err)
		}

		// Renamed and limited since to a product the triager may not know,
		// the window is read as the list of windows reads it: not at all.
		if _, err := f.store.ChangeWindow(ctx, f.admin, here.ID, obligation.WindowSaid{
			Name: "Other's second window", Hours: 24, Products: []string{"other"},
		}); err != nil {
			t.Fatal(err)
		}
		told, err := f.store.ToldAbout(ctx, f.triager, []int64{record.ID})
		if err != nil {
			t.Fatal(err)
		}
		if len(told[record.ID]) != 1 {
			t.Fatalf("the triager read %d notices, want 1", len(told[record.ID]))
		}
		named, err := f.store.WindowsNamed(ctx, f.triager, told)
		if err != nil {
			t.Fatal(err)
		}
		if name, ok := named[here.ID]; ok {
			t.Errorf("a notice names %q, a window since limited to a product the reader may not know", name)
		}
		named, err = f.store.WindowsNamed(ctx, access.Everything("a check"), told)
		if err != nil {
			t.Fatal(err)
		}
		if named[here.ID] != "Other's second window" {
			t.Errorf("read as the deployment, the notice names %v", named)
		}
	})
}

func TestANoticeIsNotBeforeTheAttackBecameKnown(t *testing.T) {
	// One of the two moments is wrong, and the record is the one already
	// kept.
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		if _, err := f.store.RecordTold(t.Context(), f.triager, record.ID, nil, "ENISA",
			knownAt.Add(-time.Hour), "An attack.", obligation.Details{}); err == nil {
			t.Error("a notice before the attack became known was recorded")
		}
		if _, err := f.store.RecordTold(t.Context(), f.triager, record.ID, nil, "ENISA",
			time.Now().Add(time.Hour), "An attack.", obligation.Details{}); err == nil {
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
			knownAt.Add(time.Hour), "An attack.", obligation.Details{})
		if !errors.Is(err, obligation.ErrNoSuchRecord) {
			t.Fatalf("somebody with nothing on the product recording a notice answered %v", err)
		}
		_, err = f.store.RecordTold(t.Context(), f.outsider, record.ID+1000, nil, "ENISA",
			knownAt.Add(time.Hour), "An attack.", obligation.Details{})
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

func TestChangingAWindowMovesEveryIncidentsEnd(t *testing.T) {
	// An end is worked out from the window as it stands, so changing the
	// window is what moves it; nothing stored holds the old end.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		early := f.window(t, "Early warning", 24)
		f.attacked(t)

		changed, err := f.store.ChangeWindow(ctx, f.admin, early.ID, obligation.WindowSaid{Name: "Early notice", Hours: 36})
		if err != nil {
			t.Fatal(err)
		}
		if changed.Name != "Early notice" || changed.Hours != 36 {
			t.Errorf("the window reads as %+v after changing it", changed)
		}
		shelf, err := f.store.Shelf(ctx, f.triager)
		if err != nil {
			t.Fatal(err)
		}
		due := shelf[0].Windows[0]
		if want := knownAt.Add(36 * time.Hour); !due.EndsAt.Equal(want) {
			t.Errorf("after changing the window it ends %s, want %s", due.EndsAt, want)
		}
	})
}

func TestAWindowIsChangedOnlyByAnAdministratorIntoANameNobodyHolds(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		early := f.window(t, "Early warning", 24)
		f.window(t, "Notification", 72)

		if _, err := f.store.ChangeWindow(ctx, f.triager, early.ID, obligation.WindowSaid{Name: "Early", Hours: 24}); !errors.Is(err,
			access.ErrDenied) {
			t.Errorf("a triager changing a window answered %v", err)
		}
		if _, err := f.store.ChangeWindow(ctx, f.admin, early.ID, obligation.WindowSaid{Name: "NOTIFICATION", Hours: 24}); !errors.Is(err,
			obligation.ErrWindowNamed) {
			t.Errorf("renaming onto a window in force answered %v", err)
		}
		// Its own name, in other capitals, is not somebody else's.
		if _, err := f.store.ChangeWindow(ctx, f.admin, early.ID, obligation.WindowSaid{Name: "early warning", Hours: 30}); err != nil {
			t.Errorf("changing a window's length under its own name answered %v", err)
		}
		if _, err := f.store.ChangeWindow(ctx, f.admin, early.ID, obligation.WindowSaid{Name: "Early", Hours: 0}); err == nil {
			t.Error("a window was changed to run for no time at all")
		}
	})
}

func TestARetiredWindowIsNeitherChangedNorAnswered(t *testing.T) {
	// Nobody counts it any more, so there is nothing to change and nothing a
	// new notice can answer. Notices already naming it keep naming it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		early := f.window(t, "Early warning", 24)
		record := f.attacked(t)
		if _, err := f.store.RecordTold(ctx, f.triager, record.ID, &early.ID, "ENISA",
			knownAt.Add(time.Hour), "An attack.", obligation.Details{}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.RetireWindow(ctx, f.admin, early.ID); err != nil {
			t.Fatal(err)
		}

		if _, err := f.store.ChangeWindow(ctx, f.admin, early.ID, obligation.WindowSaid{Name: "Early", Hours: 24}); !errors.Is(err,
			obligation.ErrNoSuchWindow) {
			t.Errorf("changing a retired window answered %v", err)
		}
		if err := f.store.RetireWindow(ctx, f.admin, early.ID); !errors.Is(err,
			obligation.ErrNoSuchWindow) {
			t.Errorf("retiring a window twice answered %v", err)
		}
		if _, err := f.store.RecordTold(ctx, f.triager, record.ID, &early.ID, "ENISA",
			knownAt.Add(2*time.Hour), "More.", obligation.Details{}); !errors.Is(err, obligation.ErrNoSuchWindow) {
			t.Errorf("a notice naming a retired window answered %v", err)
		}

		told, err := f.store.ToldAbout(ctx, f.triager, []int64{record.ID})
		if err != nil {
			t.Fatal(err)
		}
		named, err := f.store.WindowsNamed(ctx, f.triager, told)
		if err != nil {
			t.Fatal(err)
		}
		if named[early.ID] != "Early warning" {
			t.Errorf("a notice lost the name of the window it answered: %v", named)
		}
	})
}

func TestANoticeSaysWhoWhenAndWhat(t *testing.T) {
	// Each part is refused on its own, because a notice missing any of them
	// is one nobody can answer for later.
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		when := knownAt.Add(time.Hour)
		for _, tc := range []struct {
			name, recipient, said string
			at                    time.Time
		}{
			{"nobody named", "  ", "An attack.", when},
			{"a recipient longer than a name", strings.Repeat("x", obligation.RecipientLimit+1),
				"An attack.", when},
			{"nothing said", "ENISA", "  ", when},
			{"no moment", "ENISA", "An attack.", time.Time{}},
			// What was said is kept in a table nobody edits and rendered to
			// whoever answers for it, so the markdown policy and the bound
			// hold before it is stored.
			{"raw HTML in what was said", "ENISA", "<b>An attack.</b>", when},
			{"more said than the bound", "ENISA", strings.Repeat("x", triage.GroundsLimit+1), when},
		} {
			if _, err := f.store.RecordTold(t.Context(), f.triager, record.ID, nil,
				tc.recipient, tc.at, tc.said, obligation.Details{}); err == nil {
				t.Errorf("a notice with %s was recorded", tc.name)
			}
		}
	})
}

// TestANoticeIsRecordedAgainstAPerson pins that a notice names who recorded
// it, and that a subject who is not a person is told so rather than told the
// record is missing.
func TestANoticeIsRecordedAgainstAPerson(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		_, err := f.store.RecordTold(t.Context(), access.Everything("a background pass"),
			record.ID, nil, "ENISA", knownAt.Add(time.Hour), "An attack.", obligation.Details{})
		if err == nil || !strings.Contains(err.Error(), "against whoever recorded it") {
			t.Errorf("a notice recorded by no person answered %v, want the refusal naming who records one", err)
		}
	})
}

// rivalBefore returns a store whose first update of table is preceded by
// rival, run on another connection and committed before the
// statement reaches the engine.
//
// That is the interleaving a conditional write exists for: the transaction
// has read the row and is about to write it, and somebody else's write lands
// in between. SQLite has one connection and one writer, so the interleaving
// cannot happen there and the caller skips it.
func rivalBefore(t *testing.T, f *fixture, table string, rival func()) *obligation.Store {
	t.Helper()
	if f.db.Stats().MaxOpenConnections == 1 {
		t.Skip("one connection: nothing lands between a read and a write")
	}
	hooked := bun.NewDB(f.db.DB.DB, f.db.Dialect())
	hook := &interleave{table: table, rival: rival}
	hooked.AddQueryHook(hook)
	t.Cleanup(func() {
		if !hook.ran {
			t.Error("the rival never ran, so nothing landed between the read and the write")
		}
	})
	return obligation.NewStore(hooked)
}

type interleave struct {
	once  sync.Once
	table string
	rival func()
	ran   bool
}

func (h *interleave) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	// Quoted with backticks on two engines and double quotes on the others.
	named := strings.Contains(e.Query, h.table+"`") || strings.Contains(e.Query, h.table+`"`)
	if strings.HasPrefix(e.Query, "UPDATE ") && named {
		h.once.Do(func() { h.ran = true; h.rival() })
	}
	return ctx
}

func (h *interleave) AfterQuery(context.Context, *bun.QueryEvent) {}

// trailed counts the administrative trail's rows about one window.
func trailed(t *testing.T, f *fixture, name string) int {
	t.Helper()
	n, err := f.db.DB.NewSelect().TableExpr(`"admin_change"`).
		Where("about = ?", "Obligation window "+name).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTwoRetirementsAtOnceRecordOneAct(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		early := f.window(t, "Early warning", 24)
		racing := rivalBefore(t, f, "obligation_window", func() {
			if err := f.store.RetireWindow(context.Background(), f.admin, early.ID); err != nil {
				t.Errorf("the rival retirement: %v", err)
			}
		})
		if err := racing.RetireWindow(t.Context(), f.admin, early.ID); !errors.Is(err, obligation.ErrNoSuchWindow) {
			t.Errorf("retiring a window another retirement reached first answered %v", err)
		}
		// One for declaring it and one for retiring it.
		if n := trailed(t, f, "Early warning"); n != 2 {
			t.Errorf("the trail holds %d changes to the window, want 2", n)
		}
	})
}

func TestAWindowRetiredWhileBeingChangedIsNotChanged(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		early := f.window(t, "Early warning", 24)
		racing := rivalBefore(t, f, "obligation_window", func() {
			if err := f.store.RetireWindow(context.Background(), f.admin, early.ID); err != nil {
				t.Errorf("the rival retirement: %v", err)
			}
		})
		if _, err := racing.ChangeWindow(t.Context(), f.admin, early.ID,
			obligation.WindowSaid{Name: "Early warning", Hours: 48}); !errors.Is(err, obligation.ErrNoSuchWindow) {
			t.Errorf("changing a window retired since it was read answered %v", err)
		}
		if n := trailed(t, f, "Early warning"); n != 2 {
			t.Errorf("the trail holds %d changes to the window, want 2", n)
		}
	})
}

func TestANoticeAboutAnUndisclosedIssueIsRefusedToWhoMayNotReadIt(t *testing.T) {
	// Triage on the product is not enough where the issue is undisclosed:
	// the record is answered as one that is not there.
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
			Set("visibility = ?", access.Private).Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, err := f.store.RecordTold(t.Context(), f.triager, record.ID, nil, "ENISA",
			knownAt.Add(time.Hour), "An attack.", obligation.Details{})
		if !errors.Is(err, obligation.ErrNoSuchRecord) {
			t.Fatalf("a public triager recording a notice of an undisclosed attack answered %v", err)
		}
	})
}

func TestAWindowNeedsANameThatFits(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		for _, name := range []string{"  ", strings.Repeat("x", database.NameWidth+1)} {
			if _, err := f.store.DeclareWindow(t.Context(), f.admin, obligation.WindowSaid{Name: name, Hours: 24}); err == nil {
				t.Errorf("a window named %.20q was declared", name)
			}
		}
	})
}

func TestAWindowIsRetiredOnlyByAnAdministrator(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		early := f.window(t, "Early warning", 24)
		if err := f.store.RetireWindow(t.Context(), f.triager, early.ID); !errors.Is(err,
			access.ErrDenied) {
			t.Errorf("a triager retiring a window answered %v", err)
		}
	})
}

func TestTheShelfDoesNotTellAPublicReaderTheIssueIsUndisclosedElsewhere(t *testing.T) {
	// The issue is public at one place and undisclosed at another. A reader
	// who may not see undisclosed work reaches the record through the public
	// one, and that it is undisclosed anywhere is what the embargo keeps from
	// them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		var open finding.Finding
		if err := f.db.DB.NewSelect().Model(&open).Limit(1).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		hidden := open
		hidden.ID = 0
		hidden.PlaceIdentity = "place-of-libfoo-under-libbar"
		hidden.Visibility = access.Private
		if _, err := f.db.DB.NewInsert().Model(&hidden).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.attacked(t)

		shelf, err := f.store.Shelf(ctx, f.triager)
		if err != nil {
			t.Fatal(err)
		}
		if len(shelf) != 1 {
			t.Fatalf("the public triager was shown %d incidents, want the one", len(shelf))
		}
		if shelf[0].Private {
			t.Error("a public triager was told the issue is undisclosed somewhere here")
		}
		shelf, err = f.store.Shelf(ctx, f.insider)
		if err != nil {
			t.Fatal(err)
		}
		if len(shelf) != 1 || !shelf[0].Private {
			t.Errorf("a private triager was not told the issue is undisclosed here: %+v", shelf)
		}
	})
}

func TestANoticeIsReadOnlyByWhoMayBeToldOfTheAttack(t *testing.T) {
	// A notice names an attack, so it is narrowed by the record it is about:
	// somebody who may not be told of the attack is not handed what was said
	// about it, whoever asks on their behalf.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		record := f.attacked(t)
		if _, err := f.store.RecordTold(ctx, f.triager, record.ID, nil, "ENISA",
			knownAt.Add(time.Hour), "An attack.", obligation.Details{}); err != nil {
			t.Fatal(err)
		}
		told, err := f.store.ToldAbout(ctx, f.outsider, []int64{record.ID})
		if err != nil {
			t.Fatal(err)
		}
		if len(told) != 0 {
			t.Errorf("somebody with nothing on the product was handed %+v", told)
		}
		told, err = f.store.ToldAbout(ctx, f.triager, []int64{record.ID})
		if err != nil {
			t.Fatal(err)
		}
		if len(told[record.ID]) != 1 {
			t.Errorf("a triager on the product was handed %+v", told)
		}
	})
}

func TestAWindowLimitedToProductsAppliesToThoseAlone(t *testing.T) {
	// The products a window is limited to are stored, changed and read on
	// every engine, and the shelf counts the window only where it applies.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.attacked(t)
		other, err := catalog.NewStore(f.db.DB).ProductByName(ctx, "other")
		if err != nil {
			t.Fatal(err)
		}
		limited, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Early warning", Hours: 24, Products: []string{world.ProductName},
		})
		if err != nil {
			t.Fatal(err)
		}

		counted := func(t *testing.T) (products []int64, onShelf bool) {
			t.Helper()
			windows, err := f.store.Windows(ctx, f.admin)
			if err != nil {
				t.Fatal(err)
			}
			for _, window := range windows {
				if window.ID == limited.ID {
					products = window.Products
				}
			}
			shelf, err := f.store.Shelf(ctx, f.triager)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range shelf {
				for _, due := range entry.Windows {
					if due.Window.ID == limited.ID {
						onShelf = true
					}
				}
			}
			return products, onShelf
		}

		products, onShelf := counted(t)
		if len(products) != 1 || products[0] != f.product {
			t.Errorf("a window limited to the product reads as limited to %v, want [%d]",
				products, f.product)
		}
		if !onShelf {
			t.Error("a window limited to the attacked product is not counted for it")
		}

		if _, err := f.store.ChangeWindow(ctx, f.admin, limited.ID, obligation.WindowSaid{
			Name: "Early warning", Hours: 24, Products: []string{"other"},
		}); err != nil {
			t.Fatal(err)
		}
		products, onShelf = counted(t)
		if len(products) != 1 || products[0] != other.ID {
			t.Errorf("a window moved to another product reads as limited to %v, want [%d]",
				products, other.ID)
		}
		if onShelf {
			t.Error("a window limited to another product is counted for the attacked one")
		}

		if err := f.store.RetireWindow(ctx, f.admin, limited.ID); err != nil {
			t.Fatal(err)
		}
		if products, _ = counted(t); products != nil {
			t.Errorf("a retired window is still read, limited to %v", products)
		}
	})
}

// A blank product name in a window's list is refused as a name nobody
// declared. Dropped, a list of nothing but blanks declared a window over every
// product.
func TestABlankProductInAWindowsListIsRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		if _, err := f.store.DeclareWindow(t.Context(), f.admin, obligation.WindowSaid{
			Name: "Early warning", Hours: 24, Products: []string{" "},
		}); !errors.Is(err, obligation.ErrNoSuchProduct) {
			t.Errorf("a window over a blank product answered %v", err)
		}
	})
}
