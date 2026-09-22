//go:build measure

// A year of nightly scans against this, measured rather than assumed.
//
// `REQUIREMENTS.md` §4 records the gap: scan files are deleted once read and the
// interval storage was shaped so that a rebuild changing nothing writes
// nothing, which is asserted by a test — but nobody had checked the shape
// after a year of real nightly scans, and "the design says it should be fine"
// is a sentence with a word doing too much work in it.
//
// This is behind a build tag because it is a measurement and not a gate: it
// takes minutes, it asserts almost nothing, and its output is numbers to write
// down. `make measure` runs it.
package finding_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// The shape of a real switch image, from the fixture this project keeps.
//
// Scaled down by a factor named here rather than run at full size: the answer
// wanted is how the cost *grows*, and a night at full size is the same
// operation with a bigger constant. Every number this prints says which scale
// it was taken at.
const (
	// components is how many packages a build ships. The real image has 6,845.
	components = 700
	// consumers is how many containers each package sits in on average. A real
	// image reached 241,021 places from 7,035 components, so about 34.
	//
	// That reach was measured against the previous fixture and has not been
	// re-measured against the current one, which describes 190 fewer
	// components. The average is what this model uses and it is not sensitive
	// to that difference, but the 241,021 is a figure from the older document
	// rather than from the one in testdata now.
	consumers = 34
	// issues is how many distinct vulnerabilities are open. The real image had
	// about 2,600 across 7,374 issue-at-component rows, on the same older
	// document as the line above.
	issues = 260
	// nights is how many rebuilds to simulate.
	nights = 365
	// churn is the fraction of components whose version moves on a given
	// night. A build that changes nothing writes nothing, so this is the whole
	// of what a night costs — and it is the number this measurement is most
	// sensitive to, which is why it is stated rather than buried.
	churn = 0.01
	// arriving is how many issues the vulnerability database adds each night
	// that match something already shipped.
	arriving = 3
)

func TestMeasureAYearOfNightlyScans(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

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

		store := finding.NewStore(db.DB)
		graphs := graph.NewStore(db.DB)
		scans := ingest.NewStore(db.DB)
		// Somebody granted reading on the one product these builds
		// belong to. The narrowing is the ordinary one, which is what
		// the common plan carries — an administrator is no longer a
		// way to run without it .
		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{product.ID: {access.PrivateRead}}, 0)

		// A night's cost in statements, not only in seconds.
		//
		// The engine gap this measures — MySQL a night several times more
		// expensive than PostgreSQL's, and barely moving when the churn was
		// halved — is either work or round trips, and the two are told apart
		// by dividing. A cost that is flat in rows and proportional to
		// statements is paid per statement.
		statements := &counting{}
		db.AddQueryHook(statements)

		built := time.Now().UTC().Add(-time.Duration(nights) * 24 * time.Hour)
		seq := 0
		night := func(versionOf func(int) string, extra int) (finding.Applied, time.Duration, int64) {
			seq++
			built = built.Add(24 * time.Hour)
			scan, _, err := scans.Record(ctx, ingest.Arriving{
				TargetID: target.ID, ContentHash: fmt.Sprintf("hash-%d", seq),
				BuiltAt: built, ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			snap := shape(versionOf)
			if _, err := graphs.Apply(ctx, target.ID, scan.ID, snap); err != nil {
				t.Fatal(err)
			}
			run, err := store.Begin(ctx, finding.Run{
				TargetID: target.ID, Scanner: "measure",
				ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			reported := reports(versionOf, extra)
			before := statements.n.Load()
			start := time.Now()
			applied, err := store.Apply(ctx, target.ID, run.ID, reported)
			if err != nil {
				t.Fatal(err)
			}
			took := time.Since(start)
			issued := statements.n.Load() - before
			if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
				t.Fatal(err)
			}
			return applied, took, issued
		}

		// The first night is every finding opening at once, which is what an
		// installation's first scan actually is.
		first, took, issued := night(func(int) string { return "1.0" }, 0)
		t.Logf("scale: %d components x %d consumers = %d places, %d issues",
			components, consumers, components*consumers, issues)
		t.Logf("night 1 (everything opens): opened %d in %s, %d statements (%s each)",
			first.Opened, took, issued, per(took, issued))

		count := func(table string) int {
			var n int
			if err := db.DB.NewSelect().TableExpr(table).
				ColumnExpr("COUNT(*)").Scan(ctx, &n); err != nil {
				t.Fatalf("count %s: %v", table, err)
			}
			return n
		}
		report := func(label string) {
			t.Logf("%s: finding=%d scan_run=%d graph_node=%d graph_edge=%d",
				label, count("finding"), count("scan_run"),
				count("graph_node"), count("graph_edge"))
			timed(t, ctx, store, who, finding.Scope{
				ProductID: &product.ID, StreamID: &branch.ID, VariantID: &variant.ID,
			})
			timedHistory(t, ctx, store, scans, graphs, who, target.ID, product.ID)
		}
		report("after night 1")

		// Then a year of them. A component whose version moves closes every
		// finding at it and opens the same number again, which is the whole of
		// what a quiet night costs. Each component's version, carried forward.
		// A bump is permanent: a package that moved to 1.5 does not go back to
		// 1.0 tomorrow.
		//
		// The first version of this slid a window and left everything outside
		// it at 1.0, so last night's components reverted — fourteen identities
		// changing a night where the model says seven, and a version history
		// no build has. The numbers it produced were real measurements of
		// twice the churn they claimed.
		version := make([]string, components)
		for i := range version {
			version[i] = "1.0"
		}
		moved := 0
		var slowest time.Duration
		var total time.Duration
		var issuedAll int64
		for n := 2; n <= nights; n++ {
			bumped := int(float64(components) * churn)
			from := (n * bumped) % components
			for i := from; i < from+bumped && i < components; i++ {
				version[i] = fmt.Sprintf("1.%d", n)
			}
			versionOf := func(i int) string { return version[i] }
			_, took, issued := night(versionOf, (n-1)*arriving)
			total += took
			issuedAll += issued
			if took > slowest {
				slowest = took
			}
			moved += min(bumped, components-from)
			if n%73 == 0 {
				report(fmt.Sprintf("after night %d", n))
			}
		}
		measured := int64(nights - 1)
		t.Logf("a night cost %s on average, %s at worst, over %d nights",
			total/time.Duration(measured), slowest, measured)
		t.Logf("a night issued %d statements on average, costing %s each",
			issuedAll/measured, per(total, issuedAll))
		t.Logf("%d component versions moved across the year", moved)
		report("after a year")

		// What the two questions about variants cost. They are the only reads
		// here that correlate a subquery per row, and the branch is given a
		// second build first: a filter comparing a row with the other
		// variants of its branch has nothing to reach where the branch holds
		// one.
		//
		// Taken after the counts above so that the year's table describes the
		// same one build it always did.
		second, err := cat.DeclareVariant(ctx, product.ID, "mellanox", true)
		if err != nil {
			t.Fatal(err)
		}
		beside, err := cat.TargetFor(ctx, branch.ID, second.ID)
		if err != nil {
			t.Fatal(err)
		}
		versionOf := func(i int) string { return version[i] }
		scan, _, err := scans.Record(ctx, ingest.Arriving{
			TargetID: beside.ID, ContentHash: "beside", BuiltAt: built,
			ParserVersion: "measure",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := graphs.Apply(ctx, beside.ID, scan.ID, shape(versionOf)); err != nil {
			t.Fatal(err)
		}
		run, err := store.Begin(ctx, finding.Run{
			TargetID: beside.ID, Scanner: "measure",
			ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Apply(ctx, beside.ID, run.ID,
			reports(versionOf, (nights-1)*arriving)); err != nil {
			t.Fatal(err)
		}
		if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
			t.Fatal(err)
		}

		onBranch := finding.Scope{ProductID: &product.ID, StreamID: &branch.ID}
		start := time.Now()
		_, common, err := store.Groups(ctx, who, onBranch, 50, 0,
			finding.Filter{AcrossVariants: finding.EveryVariant})
		if err != nil {
			t.Fatalf("common to every variant: %v", err)
		}
		everyTook := time.Since(start)

		ofOne := finding.Scope{
			ProductID: &product.ID, StreamID: &branch.ID, VariantID: &second.ID,
		}
		start = time.Now()
		_, specific, err := store.Groups(ctx, who, ofOne, 50, 0,
			finding.Filter{AcrossVariants: finding.OnlyThisVariant})
		if err != nil {
			t.Fatalf("specific to one variant: %v", err)
		}
		onlyTook := time.Since(start)

		start = time.Now()
		_, all, err := store.Groups(ctx, who, onBranch, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatalf("the same list unnarrowed: %v", err)
		}
		plain := time.Since(start)
		t.Logf("    two builds of one branch: list %s (%d rows) · every %s (%d) · only %s (%d)",
			plain.Round(time.Millisecond), all,
			everyTook.Round(time.Millisecond), common,
			onlyTook.Round(time.Millisecond), specific)
	})
}

// shape builds the graph for one night: a root, some consumers, and every
// component under every consumer.
func shape(versionOf func(int) string) graph.Snapshot {
	snap := graph.Snapshot{Root: at("sonic", "1.0")}
	snap.Components = append(snap.Components, snap.Root)
	holders := make([]graph.Described, 0, consumers)
	for c := range consumers {
		holder := at(fmt.Sprintf("container-%d", c), "1.0")
		holders = append(holders, holder)
		snap.Components = append(snap.Components, holder)
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{
			Parent: snap.Root, Child: holder,
		})
	}
	for i := range components {
		part := at(fmt.Sprintf("package-%d", i), versionOf(i))
		snap.Components = append(snap.Components, part)
		for _, holder := range holders {
			snap.Dependencies = append(snap.Dependencies, graph.Dependency{
				Parent: holder, Child: part,
			})
		}
	}
	return snap
}

// reports is what the scanner says it found: every issue against the component
// it belongs to, plus whatever the vulnerability database has added since.
func reports(versionOf func(int) string, extra int) []finding.Reported {
	out := make([]finding.Reported, 0, issues+extra)
	for v := range issues + extra {
		part := at(fmt.Sprintf("package-%d", v%components), versionOf(v%components))
		one := finding.Reported{
			Issue: finding.Named{
				Identifier: fmt.Sprintf("CVE-2026-%05d", v),
				Severity:   [...]string{"low", "medium", "high", "critical"}[v%4],
			},
			Component: part,
		}
		// Two thirds of them name the version that fixes them, which is what
		// a real image looks like: 5,047 of 7,612 open rows were fixable on
		// the one this model is drawn from. Without it every bundle query
		// measured here reads an empty set, which is not what anybody waits
		// for.
		if v%3 != 0 {
			one.FixState, one.FixedIn = finding.FixedUpstream, "9.9"
		}
		out = append(out, one)
	}
	return out
}

// timedHistory runs the two reads that grow with the calendar rather than with
// the size of a build.
//
// Both were named as unbounded rather than measured: the receipts page reads
// every finished run of a target and every scan filed against it, whatever
// page is asked for, and then pairs them; the release comparison counts what
// is open against every build of a product. A year of nights is what tells the
// difference between a shape that grows and a shape that matters.
func timedHistory(t *testing.T, ctx context.Context, store *finding.Store,
	scans *ingest.Store, graphs *graph.Store, who access.Subject, target, product int64) {

	t.Helper()
	start := time.Now()
	first, filed, err := scans.Receipts(ctx, who, target, "", 50, 0)
	if err != nil {
		t.Fatalf("receipts: %v", err)
	}
	page := time.Since(start)

	// A later page as well as the first. The pairing is done over all of
	// history rather than over the page, so the last page should cost what the
	// first does — and if it does not, that is the answer.
	deep := 0
	if filed > 50 {
		deep = filed - 50
	}
	start = time.Now()
	last, _, err := scans.Receipts(ctx, who, target, "", 50, deep)
	if err != nil {
		t.Fatalf("receipts at %d: %v", deep, err)
	}
	back := time.Since(start)

	start = time.Now()
	releases, err := store.Releases(ctx, who, product)
	if err != nil {
		t.Fatalf("releases: %v", err)
	}
	compare := time.Since(start)

	// What each upload on the page made of the inventory, which every row of
	// that page carries. One statement for the page, over the build's node
	// rows — a year of nights is what says whether that grows with the
	// calendar, since the rows a closed interval leaves behind are what it
	// reads.
	ids := make([]int64, 0, len(first))
	for _, receipt := range first {
		ids = append(ids, receipt.Scan.ID)
	}
	start = time.Now()
	deltas, err := graphs.Deltas(ctx, who, target, ids)
	if err != nil {
		t.Fatalf("inventory deltas: %v", err)
	}
	inventory := time.Since(start)

	t.Logf("    receipts page 1 %s (%d of %d) · page at %d %s (%d) · releases %s (%d builds)",
		page.Round(time.Millisecond), len(first), filed,
		deep, back.Round(time.Millisecond), len(last),
		compare.Round(time.Millisecond), len(releases))
	t.Logf("    inventory deltas %s (%d uploads of the page answered)",
		inventory.Round(time.Millisecond), len(deltas))
}

// timed runs the queries somebody actually waits for.
func timed(t *testing.T, ctx context.Context, store *finding.Store,
	who access.Subject, scope finding.Scope) {

	t.Helper()
	start := time.Now()
	_, total, err := store.Groups(ctx, who, scope, 50, 0, finding.Filter{})
	if err != nil {
		t.Fatalf("findings list: %v", err)
	}
	list := time.Since(start)

	start = time.Now()
	due, _, err := store.RunningOut(ctx, who, finding.Scope{}, 30*24*time.Hour, 50)
	if err != nil {
		t.Fatalf("running out: %v", err)
	}
	out := time.Since(start)

	// The findings one bump would close, which is the screen a person works
	// down. Measured slow on a real deployment at 2.2 s, which is why it is
	// here: the group is over every open fixable row of every build in scope,
	// and what a page costs is a question about the whole set rather than
	// about the fifty rows it answers with.
	start = time.Now()
	bumps, bundles, err := store.Bundles(ctx, who, scope, 50, 0, finding.Filter{})
	if err != nil {
		t.Fatalf("fix bundles: %v", err)
	}
	bundled := time.Since(start)

	start = time.Now()
	points, err := store.Trend(ctx, who, finding.Scope{},
		time.Now().UTC().Add(-12*7*24*time.Hour), 7*24*time.Hour, 12, finding.Within{})
	if err != nil {
		t.Fatalf("trend: %v", err)
	}
	trend := time.Since(start)

	t.Logf("    findings list %s (%d rows) · running out %s (%d) · trend %s (%d points)",
		list.Round(time.Millisecond), total,
		out.Round(time.Millisecond), len(due),
		trend.Round(time.Millisecond), len(points))
	t.Logf("    fix bundles %s (%d of %d bumps)",
		bundled.Round(time.Millisecond), len(bumps), bundles)
}

// counting counts the statements a store issues, so a night's cost can be
// divided into work and round trips.
type counting struct{ n atomic.Int64 }

func (c *counting) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *counting) AfterQuery(context.Context, *bun.QueryEvent) {}

// per is how long one statement took, on average.
//
// The figure the engine comparison turns on. A cost that is flat in rows and
// proportional to statements is paid per statement — which points at how the
// work is batched rather than at how much of it there is.
func per(took time.Duration, statements int64) time.Duration {
	if statements <= 0 {
		return 0
	}
	return took / time.Duration(statements)
}

// bigIssues is how many distinct vulnerabilities one build carries, for the
// measurement that reproduces a page a person waits on.
//
// The year of nights above never builds a large *open* set — findings close as
// versions move, so its open population stays near 1,300 groups while its table
// grows to 148,614 rows. The bundle query scans what is open, so that model
// answers a different question from the one asked. A real switch image carried
// 272,539 open rows, 5,047 of them fixable; this reaches the same order in one
// night by carrying more issues rather than more nights.
const bigIssues = 6_000

func TestMeasureAFixBundlePage(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

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

		store := finding.NewStore(db.DB)
		scans := ingest.NewStore(db.DB)
		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{product.ID: {access.PrivateRead}}, 0)

		scan, _, err := scans.Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "bundles", BuiltAt: time.Now().UTC(),
			ParserVersion: "measure",
		})
		if err != nil {
			t.Fatal(err)
		}
		versionOf := func(int) string { return "1.0" }
		if _, err := graph.NewStore(db.DB).Apply(ctx, target.ID, scan.ID,
			shape(versionOf)); err != nil {
			t.Fatal(err)
		}
		run, err := store.Begin(ctx, finding.Run{
			TargetID: target.ID, Scanner: "measure",
			ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		applied, err := store.Apply(ctx, target.ID, run.ID, reports(versionOf, bigIssues-issues))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("opened %d findings in %s", applied.Opened, time.Since(start).Round(time.Second))
		if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
			t.Fatal(err)
		}

		var open int
		if err := db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			ColumnExpr("COUNT(*)").Where("f.closed_at IS NULL").Scan(ctx, &open); err != nil {
			t.Fatal(err)
		}
		var fixable int
		if err := db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			ColumnExpr("COUNT(*)").Where("f.closed_at IS NULL").
			Where("f.fixed_in IS NOT NULL").Where("f.fixed_in <> ?", "").
			Scan(ctx, &fixable); err != nil {
			t.Fatal(err)
		}

		scope := finding.Scope{
			ProductID: &product.ID, StreamID: &branch.ID, VariantID: &variant.ID,
		}
		// Three runs, because the first pays for a cold cache and what a person
		// waits for is the ordinary one.
		var took time.Duration
		var bundles int
		for range 3 {
			at := time.Now()
			page, total, err := store.Bundles(ctx, who, scope, 50, 0, finding.Filter{})
			if err != nil {
				t.Fatalf("fix bundles: %v", err)
			}
			took = time.Since(at)
			bundles = total
			t.Logf("fix bundles %s (%d of %d bumps)",
				took.Round(time.Millisecond), len(page), total)
		}
		// The findings list beside it, over the same rows: it reads its page
		// off an index that covers it, and the difference between the two is
		// what this measurement is for.
		at := time.Now()
		_, groups, err := store.Groups(ctx, who, scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("findings list %s (%d groups) — same rows, an index that covers it",
			time.Since(at).Round(time.Millisecond), groups)
		t.Logf("%d open, %d fixable, %d bumps", open, fixable, bundles)
	})
}

// The cost of the first scan after the deadline rule changed.
//
// The rule moved the recount from "the ranking moved" to "the answer moved",
// and a fix arriving upstream moves the answer without touching any ranking
// signal. So the first night after it lands re-clocks every open finding whose
// fix landed after it opened — which the design document calls the common case
// for an inventory made of distribution packages.
//
// The per-row update is not new; only the number of rows taking it is. What
// this answers is whether that number is a cost worth batching for, measured
// rather than assumed.
func TestMeasureTheFirstNightAfterTheDeadlineRuleChanged(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

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

		store := finding.NewStore(db.DB)
		graphs := graph.NewStore(db.DB)
		scans := ingest.NewStore(db.DB)
		statements := &counting{}
		db.AddQueryHook(statements)

		steady := func(int) string { return "1.0" }
		built := time.Now().UTC().Add(-96 * time.Hour)
		// Truncated the way a stored timestamp is, so that a date arriving
		// unchanged compares unchanged. Left at the wall clock's precision it
		// differs from what came back out of the database every night, and
		// every night then looks like the first one.
		fixArrived := built.Add(36 * time.Hour).Truncate(time.Microsecond)
		seq := 0
		night := func(withFixDate bool) (finding.Applied, time.Duration, int64) {
			seq++
			built = built.Add(24 * time.Hour)
			scan, _, err := scans.Record(ctx, ingest.Arriving{
				TargetID: target.ID, ContentHash: fmt.Sprintf("clock-%d", seq),
				BuiltAt: built, ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := graphs.Apply(ctx, target.ID, scan.ID, shape(steady)); err != nil {
				t.Fatal(err)
			}
			run, err := store.Begin(ctx, finding.Run{
				TargetID: target.ID, Scanner: "measure",
				ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			reported := reports(steady, 0)
			if withFixDate {
				// The fix arrives, dated after the finding opened. One date
				// for every night that carries it, because a feed reports when
				// a fix landed rather than a moving offset from today — and a
				// date that moved nightly would make every night look like the
				// first one.
				for i := range reported {
					if reported[i].FixState == finding.FixedUpstream {
						at := fixArrived
						reported[i].FixedAt = &at
					}
				}
			}
			before := statements.n.Load()
			start := time.Now()
			applied, err := store.Apply(ctx, target.ID, run.ID, reported)
			if err != nil {
				t.Fatal(err)
			}
			took := time.Since(start)
			issued := statements.n.Load() - before
			if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
				t.Fatal(err)
			}
			return applied, took, issued
		}

		opened, _, _ := night(false)
		t.Logf("opening night: %d findings opened", opened.Opened)

		applied, took, issued := night(true)
		t.Logf("the night the fix dates arrive: %d updated, %d statements, %s, %s per statement",
			applied.Updated, issued, took.Round(time.Millisecond),
			per(took, issued).Round(time.Microsecond))

		// The night after, where nothing has moved at all. The difference
		// between the two is what the rule change costs once, rather than what
		// a night costs for ever.
		//
		// It is not zero on every engine, and that is not this rule's
		// doing. SQLite writes nothing; PostgreSQL and MySQL rewrite every
		// fixable row again, and the same measurement taken before this rule
		// existed says the same thing. What a re-scan of unchanged data writes
		// is a question about how a timestamp survives a round trip on each
		// engine, and it is open.
		steadyApplied, steadyTook, steadyIssued := night(true)
		t.Logf("the night after: %d updated, %d statements, %s",
			steadyApplied.Updated, steadyIssued, steadyTook.Round(time.Millisecond))
	})
}
