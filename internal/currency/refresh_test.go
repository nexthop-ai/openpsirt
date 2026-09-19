package currency_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// answers is an index that says what a test tells it to, so none of this
// reaches the network. The real ones are somebody else's service and their
// answers change, which is not something to assert against.
type answers struct {
	says map[string]currency.Latest
	err  error
	// asked records every name this was asked about, in order, so a test can
	// say what was *not* asked as well as what was.
	asked *[]string
}

func (a answers) Latest(_ context.Context, name string) (currency.Latest, error) {
	*a.asked = append(*a.asked, name)
	if a.err != nil {
		return currency.Latest{}, a.err
	}
	latest, known := a.says[name]
	if !known {
		return currency.Latest{}, currency.ErrUnknown
	}
	return latest, nil
}

type component struct {
	purl    string
	checked *time.Time
	// version is what a previous pass stored. Its presence is what tells a
	// stale answer apart from a question the index could not answer, which
	// are left alone for very different lengths of time.
	version *string
}

// seed puts components in the graph and returns a refresher over them.
func seed(t *testing.T, db *database.DB, of []component,
	says map[string]currency.Latest, err error) (*currency.Refresher, *[]string) {

	t.Helper()
	ctx := t.Context()
	for i, each := range of {
		row := &graph.Component{
			Identity:        "identity-" + each.purl,
			Purl:            each.purl,
			Name:            "component",
			Version:         "1.0",
			FirstSeenAt:     time.Now().UTC(),
			LatestCheckedAt: each.checked,
			LatestVersion:   each.version,
		}
		if _, insert := db.DB.NewInsert().Model(row).Exec(ctx); insert != nil {
			t.Fatalf("seed component %d: %v", i, insert)
		}
	}
	// The pass is off unless a deployment turns it on, and `Once` enforces that
	// on every component rather than trusting `Run` to have checked — a guard
	// beside the work cannot be skipped by calling the work another way.
	if err := setting.NewStore(db.DB).Set(ctx, setting.UpstreamCurrency, setting.On); err != nil {
		t.Fatalf("turn asking on: %v", err)
	}
	asked := &[]string{}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := currency.NewRefresher(db.DB, quiet, "the-only-replica", currency.Ours{})
	r.Pause = 0
	r.Index = func(ecosystem string) currency.Asker {
		switch ecosystem {
		case "golang", "npm", "pypi", "cargo":
			return answers{says: says, err: err, asked: asked}
		}
		return nil
	}
	return r, asked
}

type stored struct {
	Purl     string     `bun:"purl"`
	Version  *string    `bun:"latest_version"`
	Released *time.Time `bun:"latest_released_at"`
	Checked  *time.Time `bun:"latest_checked_at"`
	Summary  *string    `bun:"summary"`
	Project  *string    `bun:"project_url"`
}

func read(t *testing.T, db *database.DB) map[string]stored {
	t.Helper()
	var rows []stored
	err := db.DB.NewSelect().
		TableExpr("\"component\" AS \"c\"").
		ColumnExpr("c.purl, c.latest_version, c.latest_released_at, c.latest_checked_at").
		ColumnExpr("c.summary, c.project_url").
		Scan(t.Context(), &rows)
	if err != nil {
		t.Fatalf("read components: %v", err)
	}
	out := map[string]stored{}
	for _, row := range rows {
		out[row.Purl] = row
	}
	return out
}

func each(t *testing.T, fn func(t *testing.T, db *database.DB)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)
		fn(t, db)
	})
}

func TestWhatUpstreamHasReleasedIsRecorded(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		shipped := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
		r, _ := seed(t, db, []component{
			{purl: "pkg:golang/golang.org/x/net@v0.17.0"},
		}, map[string]currency.Latest{
			"golang.org/x/net": {Version: "v0.38.0", Released: shipped},
		}, nil)

		asked, err := r.Once(t.Context())
		if err != nil {
			t.Fatalf("once: %v", err)
		}
		if asked != 1 {
			t.Fatalf("asked about %d components, expected 1", asked)
		}
		got := read(t, db)["pkg:golang/golang.org/x/net@v0.17.0"]
		if got.Version == nil || *got.Version != "v0.38.0" {
			t.Errorf("newest version is %v, expected v0.38.0", got.Version)
		}
		if got.Released == nil || !got.Released.UTC().Equal(shipped) {
			t.Errorf("released at %v, expected %v", got.Released, shipped)
		}
		if got.Checked == nil {
			t.Error("nothing recorded that we asked")
		}
	})
}

// A distribution package has a maintainer, and it is the distribution. Asking
// an upstream index when its newest release shipped says nothing about the age
// of what Debian is carrying, and answering as though it did would be worse
// than not answering.
func TestADistributionPackageIsNotAskedAbout(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		r, asked := seed(t, db, []component{
			{purl: "pkg:deb/debian/openssl@3.5.6-1"},
			// The same thing, written the way a producer that capitalizes its
			// type writes it. Every fixture purl was already lower case, so
			// the LOWER() that makes the four engines agree could be removed
			// with the suite green — and the row that got through then had no
			// index and stuck. It behaves differently per engine without it:
			// SQLite's LIKE is case-insensitive and PostgreSQL's is not.
			{purl: "pkg:DEB/debian/curl@8.5.0-2"},
			{purl: ""},
			{purl: "pkg:cargo/serde@1.0.0"},
		}, map[string]currency.Latest{"serde": {Version: "1.0.230"}}, nil)

		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		if len(*asked) != 1 || (*asked)[0] != "serde" {
			t.Fatalf("asked about %v, expected only serde", *asked)
		}
		stored := read(t, db)
		for _, purl := range []string{
			"pkg:deb/debian/openssl@3.5.6-1", "pkg:DEB/debian/curl@8.5.0-2",
		} {
			if stored[purl].Checked != nil {
				t.Errorf("%s is a distribution package and was recorded as asked about", purl)
			}
		}
	})
}

// A private module and a vendored fork both look like a package the index has
// never heard of. Recording that we asked is what stops it being asked again
// tomorrow, and every day after, forever.
func TestAPackageNobodyPublishesIsLeftAloneForAMonth(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		r, _ := seed(t, db, []component{
			{purl: "pkg:golang/github.com/example/private@v1.0.0"},
		}, map[string]currency.Latest{}, nil)

		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		got := read(t, db)["pkg:golang/github.com/example/private@v1.0.0"]
		if got.Checked == nil {
			t.Fatal("an unanswerable question was not recorded as asked")
		}
		if got.Version != nil {
			t.Errorf("a version was stored for a package nobody publishes: %v", *got.Version)
		}

		// And it is left alone for a month rather than asked again daily,
		// which is the point: this question has no answer and asking it every
		// day is thousands of pointless requests at somebody else's free
		// service.
		for _, when := range []struct {
			what  string
			later time.Duration
			due   int
		}{
			{"a day later", currency.StaleAfter + time.Hour, 0},
			{"a week later", 7 * 24 * time.Hour, 0},
			{"a month later", currency.UnknownAfter + time.Hour, 1},
		} {
			second, _ := seed(t, db, nil, nil, nil)
			at := time.Now().Add(when.later)
			second.Now = func() time.Time { return at }
			asked, err := second.Once(t.Context())
			if err != nil {
				t.Fatalf("%s: %v", when.what, err)
			}
			if asked != when.due {
				t.Errorf("%s: asked about %d, expected %d", when.what, asked, when.due)
			}
		}
	})
}

// An index having a bad day must not be recorded as an answer, or a failure
// becomes a stored fact that nothing revisits for a day.
func TestAnIndexThatFailsIsAskedAgain(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		r, _ := seed(t, db, []component{
			{purl: "pkg:pypi/django@4.2"},
		}, nil, context.DeadlineExceeded)

		asked, err := r.Once(t.Context())
		if err != nil {
			t.Fatalf("once: %v", err)
		}
		if asked != 0 {
			t.Errorf("counted %d as asked when the index failed", asked)
		}
		if read(t, db)["pkg:pypi/django@4.2"].Checked != nil {
			t.Error("a failed request was recorded as having been asked")
		}
	})
}

// Asked recently is left alone; asked long enough ago is asked again.
func TestOnlyWhatIsStaleIsAskedAgain(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		recent := time.Now().UTC().Add(-time.Hour)
		old := time.Now().UTC().Add(-2 * currency.StaleAfter)
		had := "1.0.0"
		r, asked := seed(t, db, []component{
			{purl: "pkg:cargo/fresh@1.0.0", checked: &recent, version: &had},
			{purl: "pkg:cargo/stale@1.0.0", checked: &old, version: &had},
		}, map[string]currency.Latest{
			"fresh": {Version: "9"}, "stale": {Version: "9"},
		}, nil)

		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		if len(*asked) != 1 || (*asked)[0] != "stale" {
			t.Fatalf("asked about %v, expected only the stale one", *asked)
		}
	})
}

func TestTheNameAskedComesFromTheIdentifier(t *testing.T) {
	for _, c := range []struct {
		purl      string
		ecosystem string
		name      string
		ok        bool
	}{
		{"pkg:golang/golang.org/x/net@v0.17.0", "golang", "golang.org/x/net", true},
		{"pkg:npm/%40types/node@20.1.0", "npm", "@types/node", true},
		{"pkg:pypi/django@4.2", "pypi", "django", true},
		{"pkg:cargo/serde@1.0.0?arch=amd64", "cargo", "serde", true},
		// The subpath follows the qualifiers and is neither of them.
		{"pkg:golang/example.com/m@v1#sub/dir", "golang", "example.com/m", true},
		{"", "", "", false},
		{"not-a-purl", "", "", false},
		{"pkg:golang", "", "", false},
		// A malformed escape is a refusal rather than a segment kept raw.
		// Kept, it became part of the name asked about, and what came back
		// was an answer about a different package or none at all — recorded
		// either way as this component's upstream version.
		{"pkg:npm/%zz/node@20.1.0", "", "", false},
		{"pkg:golang/example.com/%2@v1", "", "", false},
	} {
		ecosystem, name, ok := currency.Asked(c.purl)
		if ok != c.ok || ecosystem != c.ecosystem || name != c.name {
			t.Errorf("Asked(%q) = %q, %q, %v; expected %q, %q, %v",
				c.purl, ecosystem, name, ok, c.ecosystem, c.name, c.ok)
		}
	}
}

// The message this drives tells somebody that waiting for a fix is unlikely to
// work, so the evidence for it has to be a real silence rather than an
// artifact of comparing two year-numbers.
func TestUpstreamIsOnlyCalledSilentAfterAClearYear(t *testing.T) {
	for _, c := range []struct {
		what       string
		identifier string
		released   time.Time
		silent     bool
	}{
		{"released weeks before it was named",
			"CVE-2026-31431", time.Date(2025, 12, 20, 0, 0, 0, 0, time.UTC), false},
		{"released the same year",
			"CVE-2026-31431", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), false},
		{"released the whole year before",
			"CVE-2026-31431", time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC), false},
		{"silent for a clear year",
			"CVE-2026-31431", time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC), true},
		{"silent for years",
			"CVE-2021-44228", time.Date(2017, 6, 1, 0, 0, 0, 0, time.UTC), true},
		// An identifier that names no year says nothing either way, and
		// guessing would invent the fact this exists to supply.
		{"no year in the identifier",
			"GHSA-jfh8-c2jp-5v3q", time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"nothing known about upstream", "CVE-2026-31431", time.Time{}, false},
	} {
		if got := currency.NothingSince(c.identifier, c.released); got != c.silent {
			t.Errorf("%s: NothingSince(%q, %s) = %v, expected %v",
				c.what, c.identifier, c.released.Format(time.DateOnly), got, c.silent)
		}
	}
}

// The defect this exists to prevent: components whose ecosystem has no index
// filling the window and leaving nothing asked. `due` takes the oldest 200
// with never-asked first, so on a real image — 3,929 components in ecosystems
// nothing asks against 3,010 that are askable — the feature asked upstream
// about nothing at all, every cycle, for good.
//
// They are not selected at all now, which is the structural form of the same
// guarantee: the window is built from the ecosystems there is an index for
// rather than from the complement of one of them. Recording an empty answer
// for each of them, which is what it did before, got through the backlog and
// then spent a slot on every one of them again a month later.
func TestEcosystemsWithNoIndexDoNotStarveTheQueue(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		var of []component
		for i := 0; i < currency.MostPerPass; i++ {
			of = append(of, component{purl: fmt.Sprintf("pkg:generic/thing-%03d@1.0", i)})
		}
		of = append(of, component{purl: "pkg:cargo/serde@1.0.0"})
		r, asked := seed(t, db, of, map[string]currency.Latest{
			"serde": {Version: "1.0.230"},
		}, nil)

		// One pass, because the unaskable ones never enter the window: with
		// them in it, two hundred of them came first and the one component
		// with an answer was never reached.
		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		if len(*asked) != 1 || (*asked)[0] != "serde" {
			t.Fatalf("asked about %v, want the one component there is an index for", *asked)
		}
		got := read(t, db)
		if got["pkg:cargo/serde@1.0.0"].Version == nil {
			t.Error("the component there is an index for was never answered")
		}
		// And nothing was written about the ones nothing can be asked: the
		// column says when we last asked, and we did not.
		for purl, row := range got {
			if purl != "pkg:cargo/serde@1.0.0" && row.Checked != nil {
				t.Errorf("%s was recorded as asked about, and there is no index for it", purl)
			}
		}
	})
}

// A name that cannot be made into a request will never come right, so it is
// recorded rather than retried. Left retryable it starves the queue the same
// way, and one uploaded document full of such names stops the worker.
func TestANameThatCannotBeAskedAboutIsNotRetriedForever(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		r, _ := seed(t, db, []component{{purl: "pkg:golang/example.com/m@v1"}},
			nil, currency.ErrUnaskable)

		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		got := read(t, db)["pkg:golang/example.com/m@v1"]
		if got.Checked == nil {
			t.Error("a name that cannot be asked about was left due forever, " +
				"so it will fill the window on every pass from now on")
		}
	})
}

// Turning it off has to take effect without a redeploy, which is the reason
// the setting is read per cycle rather than at startup. A pass is up to 200
// requests with a timeout each, so reading it only at the top of a pass leaves
// an operator who has just turned it off waiting the better part of an hour.
func TestTurningItOffStopsTheCurrentPass(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		var of []component
		for i := 0; i < 10; i++ {
			of = append(of, component{purl: fmt.Sprintf("pkg:cargo/crate-%d@1.0", i)})
		}
		r, asked := seed(t, db, of, map[string]currency.Latest{}, nil)

		// Off again after the first component is asked about.
		settings := setting.NewStore(db.DB)
		r.Index = func(string) currency.Asker {
			return stopping{t: t, settings: settings, asked: asked}
		}
		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		if len(*asked) > 2 {
			t.Errorf("asked about %d components after it was turned off: %v",
				len(*asked), *asked)
		}
	})
}

// stopping answers once and turns the setting off while the pass is running.
type stopping struct {
	t        *testing.T
	settings *setting.Store
	asked    *[]string
}

func (s stopping) Latest(ctx context.Context, name string) (currency.Latest, error) {
	*s.asked = append(*s.asked, name)
	if err := s.settings.Set(ctx, setting.UpstreamCurrency, setting.Off); err != nil {
		s.t.Fatalf("turn asking off: %v", err)
	}
	return currency.Latest{Version: "1.0.0"}, nil
}

// An answer we already had is not thrown away because the index said 404 once.
// npm and crates.io return one for a renamed package and for some transient
// conditions, and overwriting would destroy a version we had and then sit on
// the hole for a month.
func TestAnIndexSayingNoDoesNotDestroyWhatWeAlreadyKnew(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		had := "1.0.0"
		long := time.Now().UTC().Add(-2 * currency.StaleAfter)
		r, _ := seed(t, db, []component{
			{purl: "pkg:cargo/serde@1.0.0", checked: &long, version: &had},
		}, map[string]currency.Latest{}, nil)

		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		got := read(t, db)["pkg:cargo/serde@1.0.0"]
		if got.Version == nil || *got.Version != had {
			t.Errorf("the stored version became %v; one 404 must not destroy it", got.Version)
		}
		if got.Checked == nil || !got.Checked.After(long) {
			t.Error("the time of asking was not moved on")
		}
	})
}

// counted records what an index was asked, safely enough for two replicas to
// share one — which is the case the test is about, and which has to be safe
// even when the control being tested is broken.
type counted struct {
	mu    sync.Mutex
	asked []string
}

func (c *counted) Latest(_ context.Context, name string) (currency.Latest, error) {
	c.mu.Lock()
	c.asked = append(c.asked, name)
	c.mu.Unlock()
	return currency.Latest{Version: "9.9", Released: time.Now().UTC()}, nil
}

func (c *counted) times() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.asked)
}

func TestOneReplicaAsksTheIndexes(t *testing.T) {
	// The politeness this pass is built around — a slice at a time, spaced
	// out — is a rate per deployment, not a rate per replica. Every
	// replica runs the pass and one of them asks, decided by a lease
	// rather than by all of them asking at once and each answering what
	// another already had .
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)
		// Seeded for its components and its setting; the refresher it returns
		// is not the one this drives, because this needs two of them.
		seed(t, db, []component{
			{purl: "pkg:golang/example.com/one@1.0"},
			{purl: "pkg:golang/example.com/two@1.0"},
			{purl: "pkg:golang/example.com/three@1.0"},
		}, nil, nil)

		index := &counted{}
		replicas := make([]*currency.Refresher, 2)
		for i := range replicas {
			r := currency.NewRefresher(db.DB, quiet, fmt.Sprintf("replica-%d", i), currency.Ours{})
			r.Pause = 0
			r.Index = func(string) currency.Asker { return index }
			replicas[i] = r
		}

		running, stop := context.WithCancel(ctx)
		var wg sync.WaitGroup
		for _, r := range replicas {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.Run(running, 10*time.Millisecond)
			}()
		}
		// Two waits, and they are different in kind.
		//
		// The first is for the pass to get through all three components. How
		// long that takes belongs to the engine and the machine, not to the
		// behavior being pinned, so it is waited for rather than budgeted:
		// under load on MariaDB three cycles did not fit in 300ms and the test
		// failed reporting one component asked of three, which is this pass
		// working and being interrupted.
		//
		// The second is the measurement. Both replicas keep running with
		// nothing left to do, which is when a replica that asks without the
		// lease, or a pass that failed to store what it learned, would ask
		// again. That one is a stretch of wall clock on purpose — it is a
		// soak, and a short one only makes the test weaker rather than wrong.
		waited := 0
		for index.times() < 3 && waited < 10_000 {
			time.Sleep(time.Millisecond)
			waited++
		}
		time.Sleep(300 * time.Millisecond)
		stop()
		wg.Wait()

		// Three components, asked once each by whichever replica holds the
		// lease. Asked again on a later cycle would mean the answers were not
		// stored; asked twice at once would mean both replicas were asking.
		if times := index.times(); times != 3 {
			t.Errorf("the indexes were asked %d times about 3 components (%v), want 3",
				times, index.asked)
		}
	})
}

// An index's description of a package, bounded, and the address it gives,
// judged. Both arrive over the network from somebody else and are rendered to
// staff who hold the most access.
func TestWhatAnIndexSaysIsBoundedAndItsAddressJudged(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		long := strings.Repeat("a", currency.MostSummary+120)
		r, _ := seed(t, db, []component{
			{purl: "pkg:npm/kept@1.0.0"},
			{purl: "pkg:npm/clipped@1.0.0"},
			{purl: "pkg:npm/hostile@1.0.0"},
			{purl: "pkg:npm/enormous@1.0.0"},
		}, map[string]currency.Latest{
			"kept": {
				Version: "2.0.0", Summary: "  a   label   with   spaces  ",
				Project: "https://example.test/kept",
			},
			// A publisher may put a paragraph in the one-line field, and a row
			// of a table is not where a paragraph is read.
			"clipped": {Version: "2.0.0", Summary: long},
			// A scheme a browser acts on is not encoded output. An index is a
			// third party like any other.
			"hostile": {
				Version: "2.0.0", Summary: "fine",
				Project: "javascript:alert(document.domain)",
			},
			// The summary is shortened and the address is not: a cut address
			// is a different address, and this one becomes somewhere to
			// click. The comment beside the two said both were bounded.
			"enormous": {
				Version: "2.0.0", Summary: "fine",
				Project: "https://example.test/" + strings.Repeat("a", currency.MostAddress),
			},
		}, nil)
		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		got := read(t, db)

		kept := got["pkg:npm/kept@1.0.0"]
		// Run together on one line, because a label is read in a row.
		if kept.Summary == nil || *kept.Summary != "a label with spaces" {
			t.Errorf("the summary is %v, want it collapsed to one line", kept.Summary)
		}
		if kept.Project == nil || *kept.Project != "https://example.test/kept" {
			t.Errorf("the address is %v, want what the index said", kept.Project)
		}

		clipped := got["pkg:npm/clipped@1.0.0"]
		if clipped.Summary == nil {
			t.Fatal("a long summary was dropped rather than shortened")
		}
		if n := len([]rune(*clipped.Summary)); n > currency.MostSummary {
			t.Errorf("the summary kept %d runes, more than the %d bound",
				n, currency.MostSummary)
		}

		hostile := got["pkg:npm/hostile@1.0.0"]
		// Nothing stored rather than the scheme: empty and absent are the same
		// answer here, and which one a row holds depends on whether anything
		// ever wrote the column.
		if hostile.Project != nil && *hostile.Project != "" {
			t.Errorf("a scheme a browser acts on was stored: %q", *hostile.Project)
		}
		// And the rest of the answer survived the refusal.
		if hostile.Summary == nil || *hostile.Summary != "fine" {
			t.Errorf("refusing the address lost the summary: %v", hostile.Summary)
		}
		// And refusing the address does not lose the rest of the answer.
		if hostile.Version == nil || *hostile.Version != "2.0.0" {
			t.Errorf("refusing the address lost the version: %v", hostile.Version)
		}

		enormous := got["pkg:npm/enormous@1.0.0"]
		if enormous.Project != nil && *enormous.Project != "" {
			t.Errorf("an address past the bound was stored, %d bytes of it",
				len(*enormous.Project))
		}
		if enormous.Version == nil || *enormous.Version != "2.0.0" {
			t.Errorf("refusing the address lost the version: %v", enormous.Version)
		}
	})
}

func TestARefusalTheIndexWillRepeatDoesNotHoldTheHeadOfTheWindow(t *testing.T) {
	// Every status but 200, 404 and 410 took the arm for a bad day: nothing
	// was written, so the component stayed due — and the window takes the
	// never-asked first, so the same one led every pass afterwards for ever
	// and the components behind it were never reached. A package a registry
	// withdrew, a region it will not serve and a request it will not accept
	// are all of them.
	each(t, func(t *testing.T, db *database.DB) {
		r, asked := seed(t, db, []component{
			{purl: "pkg:npm/refused@1.0.0"},
			{purl: "pkg:npm/behind-it@1.0.0"},
		}, map[string]currency.Latest{
			"behind-it": {Version: "2.0.0"},
		}, nil)
		// The first one is refused in a way the index will repeat.
		r.Index = func(ecosystem string) currency.Asker {
			if ecosystem != "npm" {
				return nil
			}
			return refusing{asked: asked, says: map[string]currency.Latest{
				"behind-it": {Version: "2.0.0"},
			}}
		}

		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		got := read(t, db)
		// Recorded as asked, so it leaves the head of the window.
		if got["pkg:npm/refused@1.0.0"].Checked == nil {
			t.Error("a refusal the index will repeat was left unrecorded, so it stays due")
		}
		// And the one behind it was reached, which is what being stuck costs.
		if got["pkg:npm/behind-it@1.0.0"].Version == nil {
			t.Error("the component behind it was never asked about")
		}
	})
}

// refusing answers one name and refuses the rest the way an index refuses
// something it will go on refusing.
type refusing struct {
	says  map[string]currency.Latest
	asked *[]string
}

func (r refusing) Latest(_ context.Context, name string) (currency.Latest, error) {
	*r.asked = append(*r.asked, name)
	if latest, known := r.says[name]; known {
		return latest, nil
	}
	return currency.Latest{}, fmt.Errorf("%w: answered 403 Forbidden", currency.ErrUnaskable)
}

func TestAPassThatLosesTheLeaseStopsAsking(t *testing.T) {
	// The lease was sized from the interval between cycles, and the comment
	// beside it stated the arithmetic that contradicts that: a pass is up to
	// two hundred requests with a timeout each, which is far past five
	// intervals. So a slow index handed the pass to a second replica
	// mid-flight and both asked — the thing a lease exists to prevent, at
	// somebody else's expense.
	each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		var of []component
		says := map[string]currency.Latest{}
		for i := range currency.RenewEvery * 3 {
			name := fmt.Sprintf("thing-%03d", i)
			of = append(of, component{purl: "pkg:cargo/" + name + "@1.0.0"})
			says[name] = currency.Latest{Version: "2.0.0"}
		}
		r, asked := seed(t, db, of, says, nil)

		// A lease of no length, so it has lapsed by the time the pass asks
		// for it again — which is what a pass outliving its lease looks like.
		currency.Asking(r, 0)
		leases := queue.NewLeases(db.DB)
		if mine, err := leases.Take(ctx, currency.AskingLease, "somebody-else", time.Hour); err != nil {
			t.Fatal(err)
		} else if !mine {
			t.Fatal("the other replica did not take the lease")
		}

		if _, err := r.Once(ctx); err != nil {
			t.Fatalf("once: %v", err)
		}
		// It gets through the first stretch and then stops, rather than
		// asking about every one of them while another replica holds the
		// lease and is asking about the same ones.
		if len(*asked) != currency.RenewEvery {
			t.Errorf("asked about %d components after losing the lease, want the %d "+
				"it had already started", len(*asked), currency.RenewEvery)
		}
	})
}

// A name this deployment calls its own never reaches an index.
//
// A pass sends a component's name, and for something built here
// that is the name of a project, a team or a product nobody has announced. The
// assertion is on what was asked rather than on what was stored, because the
// two are recorded identically on purpose and a check on storage alone would
// pass against a version that asked and then threw the answer away.
func TestANameOfOursIsNotAskedAbout(t *testing.T) {
	each(t, func(t *testing.T, db *database.DB) {
		// The second one already has an answer, which is the deployment that
		// had asking turned on before any of this existed. Everything stored
		// against it came from sending the name that stops here.
		had, shipped := "1.4.0", time.Now().UTC().Add(-90*24*time.Hour)
		r, asked := seed(t, db, []component{
			{purl: "pkg:golang/github.com/nexthop-ai/openpsirt@v1.0.0"},
			{purl: "pkg:npm/%40nexthop/agent@1.0.0", checked: &shipped, version: &had},
			{purl: "pkg:cargo/serde@1.0.0"},
		}, map[string]currency.Latest{"serde": {Version: "1.0.230"}}, nil)
		r.Ours = currency.Ourselves("https://nexthop.ai", nil)

		count, err := r.Once(t.Context())
		if err != nil {
			t.Fatalf("once: %v", err)
		}
		if len(*asked) != 1 || (*asked)[0] != "serde" {
			t.Fatalf("asked about %v, expected only serde", *asked)
		}
		if count != 1 {
			t.Fatalf("counted %d asked about, expected 1: a name held back was not asked about", count)
		}
		// Recorded all the same. Left unrecorded it would stay due for ever,
		// and the window takes the never-asked first — so it would hold the
		// head of every pass afterwards with the components behind it never
		// reached, which is the failure the arm beside it exists for.
		got := read(t, db)
		for _, purl := range []string{
			"pkg:golang/github.com/nexthop-ai/openpsirt@v1.0.0",
			"pkg:npm/%40nexthop/agent@1.0.0",
		} {
			if got[purl].Checked == nil {
				t.Errorf("%s was held back and left due for ever", purl)
			}
			// Dropped rather than left. Kept, the version stays on the
			// screen with nothing that will ever refresh it, the component
			// never reaches the report of what was held back, and the row
			// goes stale in a day rather than in thirty — one of the two
			// hundred slots every day for ever, sending nothing.
			if got[purl].Version != nil {
				t.Errorf("%s was held back and keeps the version an index gave it", purl)
			}
			if got[purl].Released != nil || got[purl].Summary != nil || got[purl].Project != nil {
				t.Errorf("%s was held back and keeps what an index said about it", purl)
			}
		}
	})
}

// A scan's own subject is folded in as the pass runs.
//
// The roots come from the database rather than from configuration, so a
// product declared this morning is one whose name does not leave this
// afternoon. Read per pass for that reason, and this is what says so: the
// refresher is built holding nothing and holds the root's owner back anyway.
func TestWhatWasScannedIsHeldBack(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		r, asked := seed(t, w.DB, []component{
			{purl: "pkg:golang/github.com/example-corp/product@v2.0.0"},
			{purl: "pkg:golang/github.com/example-corp/internal-lib@v1.0.0"},
			{purl: "pkg:cargo/serde@1.0.0"},
		}, map[string]currency.Latest{"serde": {Version: "1.0.230"}}, nil)
		carried(t, w, "pkg:golang/github.com/example-corp/product@v2.0.0",
			"pkg:golang/github.com/example-corp/product@v2.0.0",
			"pkg:golang/github.com/example-corp/internal-lib@v1.0.0")

		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		if len(*asked) != 1 || (*asked)[0] != "serde" {
			t.Fatalf("asked about %v, expected only serde: the root's owner was not held back", *asked)
		}
	})
}

// carried puts seeded components into the fixture's build, under a scan that
// declared root as the identifier of the thing it was about.
//
// The identifier is on the scan rather than on a component, which is where a
// build's declaration of itself is kept: the component standing for the
// product is stored by its name alone, so that a version on it does not give
// the product a new identity every night.
func carried(t *testing.T, w *fixture.World, root string, purls ...string) {
	t.Helper()
	ctx := t.Context()
	scan := &ingest.Scan{
		TargetID: w.Target.ID, ContentHash: fmt.Sprintf("hash-%d", time.Now().UnixNano()),
		BuiltAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
		ParserVersion: "test", Status: ingest.Accepted, RootIdentifier: root,
	}
	if _, err := w.DB.DB.NewInsert().Model(scan).Exec(ctx); err != nil {
		t.Fatalf("record a scan: %v", err)
	}
	for _, purl := range purls {
		var id int64
		err := w.DB.DB.NewSelect().TableExpr(`"component" AS "c"`).
			ColumnExpr("c.id").Where("c.purl = ?", purl).Scan(ctx, &id)
		if err != nil {
			t.Fatalf("find %s: %v", purl, err)
		}
		node := &graph.Node{
			TargetID: w.Target.ID, ComponentID: id, OpenedScanID: scan.ID,
		}
		if _, err := w.DB.DB.NewInsert().Model(node).Exec(ctx); err != nil {
			t.Fatalf("put %s in the build: %v", purl, err)
		}
	}
}
