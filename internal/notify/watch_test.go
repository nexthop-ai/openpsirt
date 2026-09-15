package notify_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

func TestTheWatchTellsAdministratorsWhatHasGoneQuiet(t *testing.T) {
	// The pass that makes a condition real. A build nothing has been filed
	// against is something an administrator is told; when a scan arrives
	// the alert goes without anybody dismissing it, which is the whole of
	// conditions clearing, events acknowledged and the reason these are
	// not events.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		// Somebody who is not an administrator, to check that the
		// tool's own health is not everybody's business.
		reader, err := rights.Ensure(ctx, "reader@example.com", "Reader", nil)
		if err != nil {
			t.Fatal(err)
		}

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

		// Declared a month ago. A build declared a moment ago is not quiet —
		// it is new — and the threshold is measured from when it was declared
		// precisely so that the two are told apart.
		if _, err := db.DB.NewUpdate().Table("target").
			Set("created_at = ?", time.Now().UTC().Add(-30*24*time.Hour)).
			Where("id = ?", target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		watch := notify.NewWatch(db.DB, quiet)
		seeing := func(who *access.Account) int {
			t.Helper()
			_, total, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, who), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return total
		}

		// Declared and never filed against, which is the same failure as
		// having stopped — caught earlier.
		opened, cleared, err := watch.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if opened != 1 || cleared != 0 {
			t.Fatalf("a build nothing was filed against: opened %d cleared %d, want 1 and 0",
				opened, cleared)
		}
		if n := seeing(admin); n != 1 {
			t.Errorf("the administrator was told %d things, want 1", n)
		}
		if n := seeing(reader); n != 0 {
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
		if opened != 0 || cleared != 1 {
			t.Errorf("after a scan arrived: opened %d cleared %d, want 0 and 1", opened, cleared)
		}
		if n := seeing(admin); n != 0 {
			t.Errorf("the alert should have cleared itself, %d still waiting", n)
		}
	})
}

func TestAnEmbargoPastItsDateIsToldToAdminsAndWhoeverHoldsIt(t *testing.T) {
	// Reaching the date discloses nothing — it escalates. So this is a
	// condition rather than an event: it holds while the date has passed
	// and nothing has been decided, and it clears when somebody moves the
	// date or discloses, because both of those are answering it.
	//
	// Who hears about it is the careful part. Every one of these is a
	// finding nobody has announced, so the alert is a disclosure in its
	// own right.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		owner, err := rights.Ensure(ctx, "owner@example.com", "Owner", nil)
		if err != nil {
			t.Fatal(err)
		}
		outsider, err := rights.Ensure(ctx, "public@example.com", "Public", nil)
		if err != nil {
			t.Fatal(err)
		}

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, owner.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		// Holds the ordinary right and no more, so undisclosed work — and any
		// alert about it — is not theirs to see.
		if err := rights.GrantRole(ctx, outsider.ID, product.ID, access.PublicTriage); err != nil {
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
		// New, so it is not also quiet — this test is about one condition.
		if _, err := db.DB.NewUpdate().Table("target").
			Set("created_at = ?", time.Now().UTC()).
			Where("id = ?", target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		embargoed(t, db, target.ID, "SONIC-2026-0001", owner.ID,
			time.Now().UTC().Add(-24*time.Hour))

		// A second one, held by somebody who may not read undisclosed work
		// here. An assignment can outlive the role that allowed it, and
		// delivering this to them would hand over the thing the role was
		// withdrawn to stop.
		embargoed(t, db, target.ID, "SONIC-2026-0002", outsider.ID,
			time.Now().UTC().Add(-24*time.Hour))

		watch := notify.NewWatch(db.DB, quiet)
		seeing := func(who *access.Account) int {
			t.Helper()
			_, total, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, who), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return total
		}

		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := seeing(admin); n != 2 {
			t.Errorf("the administrator was told %d things about passed dates, want 2", n)
		}
		if n := seeing(owner); n != 1 {
			t.Errorf("whoever holds one was told %d things, want 1", n)
		}
		// Holding it is not enough. They may not read undisclosed work here,
		// and the alert says an undisclosed finding exists.
		if n := seeing(outsider); n != 0 {
			t.Errorf("somebody who may not read undisclosed work was told %d things", n)
		}

		// Moving the date answers it, and the alert goes without anybody
		// dismissing anything — which is the whole reason this is a condition.
		if _, err := db.DB.NewUpdate().Table("finding").
			Set("disclose_at = ?", time.Now().UTC().Add(30*24*time.Hour)).
			Where("kind = ?", finding.Entered).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		_, cleared, err := watch.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if cleared == 0 {
			t.Error("the date moved and the alert stayed")
		}
		if n := seeing(admin); n != 0 {
			t.Errorf("the administrator still sees %d after the dates moved", n)
		}
		if n := seeing(owner); n != 0 {
			t.Errorf("whoever holds it still sees %d after the date moved", n)
		}
	})
}

// embargoed writes one undisclosed finding past its disclosure date, held by
// somebody.
func embargoed(t *testing.T, db *database.DB, targetID int64, identifier string,
	owner int64, at time.Time) {
	t.Helper()
	ctx := t.Context()
	ids, err := finding.NewVulnerabilities(db.DB).Intern(ctx,
		[]finding.Named{{Identifier: identifier, Severity: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	components := graph.NewComponents(db.DB)
	interned, err := components.Intern(ctx, []graph.Described{
		{Purl: "pkg:generic/sonic@1.0", Name: "sonic", Version: "1.0"},
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
		TargetID: targetID, Kind: finding.Entered, Visibility: access.Private,
		VulnerabilityID: ids[identifier], ComponentID: componentID,
		PlaceIdentity: "place-of-" + identifier, LastChangedAt: now, OpenedAt: now,
		DiscloseAt: &at, AssignedTo: &owner, AssignedAt: &now,
	}
	if _, err := db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatal(err)
	}
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
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		branch, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		tag, err := cat.DeclareStream(ctx, product.ID, "v1.0", catalog.Tag, &branch.ID)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		released, err := cat.TargetFor(ctx, tag.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		inProgress, err := cat.TargetFor(ctx, branch.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}

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
			Set("closed_at = ?", time.Now().UTC()).
			Where("target_id = ?", released.ID).Exec(ctx); err != nil {
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
	person, err := rights.Ensure(t.Context(), identity, "", access.Stated(admin))
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
		PlaceIdentity: "place-of-" + identifier, LastChangedAt: now, OpenedAt: now,
	}
	if _, err := db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatal(err)
	}
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
	if err := db.DB.NewSelect().Model(&person).Where("id = ?", who).
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	var held []access.Grant
	if err := db.DB.NewSelect().Model(&held).
		Where("person_id = ?", who).Where("active = ?", true).
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

func TestAnEmbargoComingUpClearsForWhoeverStopsHoldingIt(t *testing.T) {
	// The coming and the arrived conditions are one function apart, told apart
	// by a lead time — and it read the people already being told about the
	// arrived one whichever it was computing. Reconcile makes a person's open
	// set exactly what it is handed, so anybody who was neither an
	// administrator nor currently holding the finding was never handed a list
	// for this kind, was never reconciled, and their alert stood indefinitely
	// with nothing able to clear it. That alert names the issue and the
	// product, and the link is the embargoed path.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		held, err := rights.Ensure(ctx, "held@example.com", "Held", nil)
		if err != nil {
			t.Fatal(err)
		}
		next, err := rights.Ensure(ctx, "next@example.com", "Next", nil)
		if err != nil {
			t.Fatal(err)
		}

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		for _, who := range []*access.Account{held, next} {
			if err := rights.GrantRole(ctx, who.ID, product.ID, access.PrivateTriage); err != nil {
				t.Fatal(err)
			}
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
		if _, err := db.DB.NewUpdate().Table("target").
			Set("created_at = ?", time.Now().UTC()).
			Where("id = ?", target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// Inside the lead time and not yet arrived, which is the coming
		// condition and not the arrived one.
		embargoed(t, db, target.ID, "SONIC-2026-0003", held.ID,
			time.Now().UTC().Add(24*time.Hour))

		watch := notify.NewWatch(db.DB, quiet)
		seeing := func(who *access.Account) int {
			t.Helper()
			_, total, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, who), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return total
		}

		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := seeing(held); n != 1 {
			t.Fatalf("whoever holds it was told %d things about a date coming, want 1", n)
		}
		if n := seeing(admin); n != 1 {
			t.Errorf("the administrator was told %d things, want 1", n)
		}

		// The work is handed on. The previous holder is now neither an
		// administrator nor holding it, so nothing else will ever hand them a
		// list for this kind.
		if _, err := db.DB.NewUpdate().Table("finding").
			Set("assigned_to = ?", next.PartyID).
			Where("kind = ?", finding.Entered).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := seeing(held); n != 0 {
			t.Errorf("the previous holder still sees %d alerts about an embargo "+
				"that is no longer theirs", n)
		}
		if n := seeing(next); n != 1 {
			t.Errorf("whoever holds it now was told %d things, want 1", n)
		}
	})
}
