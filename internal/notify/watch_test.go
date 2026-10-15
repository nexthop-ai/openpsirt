// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestTheWatchTellsAdministratorsWhatHasGoneQuiet(t *testing.T) {
	// The pass that makes a condition real. A build nothing has been filed
	// against is something an administrator is told; when a scan arrives
	// the alert goes without anybody dismissing it, which is the whole of a
	// condition clearing itself and the reason these are not events.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		// Somebody who is not an administrator, to check that the
		// tool's own health is not everybody's business.
		reader, err := rights.Ensure(ctx, "reader@example.com", "Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Somebody who administers only by being named in configuration,
		// which is the deployment's way back in and the one administrator
		// some deployments have.
		if _, err := rights.NameBootstrapAdmins(ctx, []string{"operator@example.com"}); err != nil {
			t.Fatal(err)
		}
		operator, err := rights.ByIdentity(ctx, "operator@example.com")
		if err != nil {
			t.Fatal(err)
		}

		target := w.Target

		// Declared a month ago. A build declared a moment ago is not quiet —
		// it is new — and the threshold is measured from when it was declared
		// precisely so that the two are told apart.
		if _, err := db.DB.NewUpdate().Table("target").
			Set(`"created_at" = ?`, time.Now().UTC().Add(-30*24*time.Hour)).
			Where(`"id" = ?`, target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		watch := notify.NewWatch(db.DB, quiet)

		// Declared and never filed against, which is the same failure as
		// having stopped — caught earlier. One alert for each administrator.
		opened, cleared, err := watch.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if opened != 2 || cleared != 0 {
			t.Fatalf("a build nothing was filed against: opened %d cleared %d, want 2 and 0",
				opened, cleared)
		}
		if n := waiting(t, db, admin); n != 1 {
			t.Errorf("the administrator was told %d things, want 1", n)
		}
		if n := waiting(t, db, operator); n != 1 {
			t.Errorf("the administrator named in configuration was told %d things, want 1", n)
		}
		if n := waiting(t, db, reader); n != 0 {
			t.Errorf("somebody who administers nothing was told %d things", n)
		}

		// Running it again says the same thing, so nothing changes.
		if opened, cleared, err = watch.Once(ctx); err != nil || opened != 0 || cleared != 0 {
			t.Errorf("a second sweep opened %d cleared %d (err %v), want nothing",
				opened, cleared, err)
		}

		// A scan arrives, so it is no longer quiet and the alert clears itself.
		if _, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "fresh",
			BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "test",
		}); err != nil {
			t.Fatal(err)
		}
		opened, cleared, err = watch.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if opened != 0 || cleared != 2 {
			t.Errorf("after a scan arrived: opened %d cleared %d, want 0 and 2", opened, cleared)
		}
		if n := waiting(t, db, admin); n != 0 {
			t.Errorf("the alert should have cleared itself, %d still waiting", n)
		}
	})
}

// Somebody who stops being an administrator stops being told what only
// administrators are, the last of them included.
func TestAnAlertForAdministratorsClearsForWhoeverStopsBeingOne(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		rights := access.NewStore(db.DB)
		first, err := rights.Ensure(ctx, "first@example.com", "First", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		second, err := rights.Ensure(ctx, "second@example.com", "Second", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		target := w.Target
		if _, err := db.DB.NewUpdate().Table("target").
			Set(`"created_at" = ?`, time.Now().UTC().Add(-30*24*time.Hour)).
			Where(`"id" = ?`, target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		watch := notify.NewWatch(db.DB, quiet)
		quietFor := func(who *access.Account) int {
			t.Helper()
			n, err := db.DB.NewSelect().Model((*notify.Notification)(nil)).
				Where(`"person_id" = ?`, who.ID).Where(`"kind" = ?`, notify.BuildQuiet).
				Where(`"cleared_at" IS NULL`).Count(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return int(n)
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if quietFor(first) != 1 || quietFor(second) != 1 {
			t.Fatalf("the administrators were told %d and %d things, want 1 each",
				quietFor(first), quietFor(second))
		}

		for _, demoted := range []*access.Account{first, second} {
			if _, err := rights.Ensure(ctx, demoted.Identity, "", new(false), nil); err != nil {
				t.Fatal(err)
			}
			if _, _, err := watch.Once(ctx); err != nil {
				t.Fatal(err)
			}
			if n := quietFor(demoted); n != 0 {
				t.Errorf("%s stopped administering and is still told %d things", demoted.Identity, n)
			}
		}
	})
}

func TestACriticalOnAReleaseTellsWhoeverMayActOnIt(t *testing.T) {
	// which was decided and described as behavior and never built. The
	// stated purpose is a sentence somebody says out loud: "this release
	// has a critical, we need to cut a new one."
	//
	// A tag, not a branch: a critical on a branch is ordinary work in
	// progress, and sending both would make the alert as common as the
	// findings list. And to whoever may read it and act on it rather than
	// to administrators, because this one names an issue at a build —
	// which is finding content, and an administrator no longer reads a
	// product by administering it.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		rights := access.NewStore(db.DB)
		product := w.Product
		released := w.TargetFor(w.Tag, w.Customer)
		inProgress := w.Target

		// Somebody who triages this product, an administrator holding nothing,
		// and somebody who only reads.
		triager := recordPerson(t, rights, "triager@example.com", false, product.ID, access.PublicTriage)
		admin := recordPerson(t, rights, "admin@example.com", true, 0, "")
		reader := recordPerson(t, rights, "reader@example.com", false, product.ID, access.PublicRead)

		critical(t, db, released.ID, "CVE-2026-SHIPPED", "critical")
		critical(t, db, inProgress.ID, "CVE-2026-BRANCH", "critical")

		watch := notify.NewWatch(db.DB, quiet)
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}

		named := func(who int64) []string {
			t.Helper()
			rows, _, err := notify.NewStore(db.DB).Waiting(ctx, asksByID(t, db, who), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			var about []string
			for _, row := range rows {
				if row.Kind == notify.CriticalOnRelease {
					about = append(about, row.Body)
				}
			}
			return about
		}

		told := named(triager)
		if len(told) != 1 {
			t.Fatalf("a triager was told %d things about a release, want 1: %v", len(told), told)
		}
		if !strings.Contains(told[0], "CVE-2026-SHIPPED") {
			t.Errorf("the alert does not name the issue: %q", told[0])
		}
		if strings.Contains(told[0], "CVE-2026-BRANCH") {
			t.Errorf("a critical on a branch was reported as being on a release: %q", told[0])
		}

		// A reader is not interrupted. They may read it, so this discloses
		// nothing to them — but an alert exists to interrupt somebody who can
		// act, and reading is not acting. It is on their findings list either
		// way.
		if got := named(reader); len(got) != 0 {
			t.Errorf("somebody who can only read was interrupted: %v", got)
		}
		// An administrator holding nothing on the product is not told, because
		// they may not read the finding it names.
		if got := named(admin); len(got) != 0 {
			t.Errorf("an administrator holding nothing was told about a finding: %v", got)
		}

		// Answering it clears the alert, with nobody dismissing anything.
		if _, err := db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"closed_at" = ?`, time.Now().UTC()).
			Where(`"target_id" = ?`, released.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if got := named(triager); len(got) != 0 {
			t.Errorf("the alert stands after the finding closed: %v", got)
		}
	})
}

// recordPerson records somebody, optionally granting one role on a product.
func recordPerson(t *testing.T, rights *access.Store, identity string, admin bool,
	productID int64, role access.Role) int64 {
	t.Helper()
	person, err := rights.Ensure(t.Context(), identity, "", new(admin), nil)
	if err != nil {
		t.Fatal(err)
	}
	if role != "" {
		if err := rights.GrantRole(t.Context(), person.ID, productID, role); err != nil {
			t.Fatal(err)
		}
	}
	return person.ID
}

// critical writes an open finding of this severity against a build.
func critical(t *testing.T, db *database.DB, targetID int64, identifier, severity string) {
	t.Helper()
	ctx := t.Context()
	ids, err := finding.NewVulnerabilities(db.DB).Intern(ctx,
		[]finding.Named{{Identifier: identifier, Severity: severity}})
	if err != nil {
		t.Fatal(err)
	}
	interned, err := graph.NewComponents(db.DB).Intern(ctx, []graph.Described{
		{Purl: "pkg:generic/libnl@3.7.0", Name: "libnl", Version: "3.7.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var componentID int64
	for _, id := range interned {
		componentID = id
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := &finding.Finding{
		TargetID: targetID, Kind: finding.Vulnerable, Visibility: access.Public,
		VulnerabilityID: ids[identifier], ComponentID: componentID,
		PlaceIdentity: "place-of-" + identifier, OpenedAt: now,
	}
	if _, err := db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// waiting is how many notifications somebody is being shown.
func waiting(t *testing.T, db *database.DB, who *access.Account) int {
	t.Helper()
	_, total, err := notify.NewStore(db.DB).Waiting(t.Context(), asks(t, db, who), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	return total
}

// asks is the subject that person really is: the grants they hold, read back
// from the database, and the cases they were brought into.
//
// Not a hand-built subject with no grants. Reading the notification area is
// narrowed by what somebody may read now, so a subject carrying no grants is a
// person who may read nothing — which is not what these tests are about, and
// which the read did not notice until it began narrowing. Built here rather
// than through Resolve because that refuses somebody holding nothing, and
// "told nothing" is exactly what some of these assert.
func asks(t *testing.T, db *database.DB, who *access.Account) access.Subject {
	t.Helper()
	return asksByID(t, db, who.ID)
}

// asksByID is asks for a caller holding the person's number rather than the
// account.
func asksByID(t *testing.T, db *database.DB, who int64) access.Subject {
	t.Helper()
	var person access.Account
	if err := db.DB.NewSelect().Model(&person).Where(`"id" = ?`, who).
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	var held []access.Grant
	if err := db.DB.NewSelect().Model(&held).
		Where(`"person_id" = ?`, who).Where(`"active" = ?`, true).
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	grants := map[int64][]access.Role{}
	for _, grant := range held {
		grants[grant.ProductID] = append(grants[grant.ProductID], grant.Role)
	}
	cases, err := access.NewStore(db.DB).CasesOf(t.Context(), who)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPerson(person.ID, person.Identity, person.IsAdmin,
		grants, person.PartyID).OnCases(cases)
}

func TestTheWatchTellsAdministratorsWhenSomethingIsHiddenWithNobodyAgreeing(t *testing.T) {
	// The report that has to come back empty, asked as a condition. Empty
	// every time is a report nobody opens — checked twice, seen to be empty,
	// stopped — so it gets read after something has gone wrong rather than
	// before. This is the other way round: silence unless it has something to
	// say, and the saying reaches somebody who did not go looking.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := rights.Ensure(ctx, "reader@example.com", "Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		aScannedTarget(t, w)
		product := w.Product
		watch := notify.NewWatch(db.DB, quiet)
		hearing := func(who *access.Account) string {
			t.Helper()
			rows, _, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, who), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Kind == notify.RiskUnagreed {
					return row.Body
				}
			}
			return ""
		}

		// A deployment where the control is holding says nothing at all.
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if body := hearing(admin); body != "" {
			t.Fatalf("nothing is hidden and the alert says %q", body)
		}

		// A dismissal standing with nobody behind it, written the way the
		// failure would arrive: the row exists and no agreement does.
		hideSomething(t, db, product.ID)
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		body := hearing(admin)
		if body == "" {
			t.Fatal("a dismissal stands with nobody agreeing and nobody was told")
		}
		if !strings.Contains(body, "One judgment") {
			t.Errorf("the alert says %q, want it to count what stands", body)
		}
		// The fact and a link. The rows are what the report is for, and this is
		// a message that may leave the deployment.
		if strings.Contains(body, "CVE-") || strings.Contains(body, "openssl") {
			t.Errorf("the alert names what it is about: %q", body)
		}
		if n := hearing(reader); n != "" {
			t.Errorf("somebody who administers nothing was told %q", n)
		}
	})
}

// hideSomething writes a dismissal that stands with nobody's agreement behind
// it, straight to the tables — which is the only way the row exists at all.
func hideSomething(t *testing.T, db *database.DB, productID int64) {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	who, err := access.NewStore(db.DB).Ensure(ctx, "triager@example.com", "Triager", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	interned, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
		{Identifier: "CVE-2026-7777", Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	reason := string(triage.CodeNotPresent)
	// The typed models rather than maps of column names, so the generated key
	// comes back the way bun returns one. Asking the driver for it works on
	// one engine and is unsupported on another.
	claim := &triage.Claim{
		Kind: triage.FindingClaim, ProposedBy: who.ID, ProposedAt: now,
		Outcome: triage.NotApplicable, Justification: &reason,
	}
	if _, err := db.DB.NewInsert().Model(claim).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	key := "live"
	decision := &triage.Decision{
		ClaimID: claim.ID, ProductID: productID,
		VulnerabilityID: interned["CVE-2026-7777"],
		PlaceIdentity:   "openssl", Visibility: access.Public,
		NeedsApproval: true, State: triage.Approved, LiveKey: &key,
		ProposedBy: who.ID, ProposedAt: now,
	}
	if _, err := db.DB.NewInsert().Model(decision).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// ranOn records a finished run that stated a data version, this many days ago.
// A quiet build whose uploads are being turned away says so, and why, rather
// than that nothing has arrived.
func TestAQuietBuildBeingRefusedSaysWhyItIsRefused(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		product := w.Product
		admin := recordPerson(t, rights, "admin@example.com", true, product.ID, "")
		target := w.Target
		if _, err := db.DB.NewUpdate().Table("target").
			Set(`"created_at" = ?`, time.Now().UTC().Add(-30*24*time.Hour)).
			Where(`"id" = ?`, target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := ingest.NewStore(db.DB).Refused(ctx, access.Everything("the pipeline"),
			ingest.Refusal{TargetID: target.ID, Reason: "the inventory could not be read"}); err != nil {
			t.Fatal(err)
		}
		sweep(t, db)
		told := openFor(t, db, admin, notify.BuildQuiet)
		if len(told) != 1 || !strings.Contains(told[0], "turned away on") ||
			!strings.Contains(told[0], "the inventory could not be read") {
			t.Errorf("the administrator was told %q", told)
		}
	})
}

// An issue being exploited on a release is told to whoever may act on it,
// whatever its rating.
func TestAnExploitedIssueOnAReleaseIsToldWhateverItsRating(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		product := w.Product
		released := w.TargetFor(w.Tag, w.Customer)
		triager := recordPerson(t, rights, "triager@example.com", false, product.ID, access.PublicTriage)

		critical(t, db, released.ID, "CVE-2026-EXPLOITED", "high")
		if _, err := db.DB.NewUpdate().Table("finding").
			Set(`"urgency_exploited" = ?`, true).
			Where(`"target_id" = ?`, released.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		sweep(t, db)
		told := openFor(t, db, triager, notify.CriticalOnRelease)
		if len(told) != 1 || !strings.Contains(told[0], "is being exploited") {
			t.Errorf("the triager was told %q", told)
		}
	})
}

// A place a supplier's statement answers on some routes is open for the rest
// and is not work, so nobody is told about it.
func TestACriticalASupplierAnswersIsNotTold(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		product := w.Product
		released := w.TargetFor(w.Tag, w.Customer)
		triager := recordPerson(t, rights, "triager@example.com", false, product.ID, access.PublicTriage)

		critical(t, db, released.ID, "CVE-2026-ANSWERED", "critical")
		if _, err := db.DB.NewUpdate().Table("finding").
			Set(`"stated_by" = ?`, 1).
			Where(`"target_id" = ?`, released.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		sweep(t, db)
		if told := openFor(t, db, triager, notify.CriticalOnRelease); len(told) != 0 {
			t.Errorf("the triager was told %q about a place a supplier answers", told)
		}
	})
}
