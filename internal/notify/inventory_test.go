// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// An upload that changed much of what a build is made of. What these pin is
// the two halves of the threshold — a share of the inventory and a floor under
// it — and that who hears is who may read the product.

// build is a world with somebody who may read its product, and a way to file
// inventories against it one after another.
type build struct {
	world *fixtures.World
	db    *database.DB
	scans *ingest.Store
	graph *graph.Store
	// reader may read the product. watcher may not, and holds nothing
	// anywhere.
	reader, watcher *access.Account
	built           time.Time
	seq             int
}

func eachBuild(t *testing.T, fn func(t *testing.T, b *build)) {
	t.Helper()
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		reader := w.DeclarePerson("reader@example.com", "A Reader", false)
		watcher := w.DeclarePerson("stranger@example.com", "A Stranger", false)
		if err := w.Access.GrantRole(t.Context(), reader.ID, w.Product.ID, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		fn(t, &build{
			world: w, db: w.DB, scans: ingest.NewStore(w.DB.DB), graph: graph.NewStore(w.DB.DB),
			reader: reader, watcher: watcher,
			built: time.Now().UTC().Add(-48 * time.Hour),
		})
	})
}

// holding files an inventory of these names, each at one version, and tells
// whoever should hear about it.
func (b *build) holding(t *testing.T, names ...string) {
	t.Helper()
	root := graph.Described{Purl: "pkg:generic/sonic@2.4.0", Name: "sonic", Version: "2.4.0"}
	snap := graph.Snapshot{Root: root}
	for _, name := range names {
		at := graph.Described{
			Purl: "pkg:generic/" + name, Name: strings.Split(name, "@")[0],
			Version: strings.Split(name, "@")[1],
		}
		snap.Components = append(snap.Components, at)
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: at})
	}

	b.seq++
	b.built = b.built.Add(time.Hour)
	rec, outcome, err := b.scans.Record(t.Context(), ingest.Arriving{
		TargetID: b.world.Target.ID, ContentHash: fmt.Sprintf("hash-%d", b.seq),
		BuiltAt: b.built, ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record upload %d: outcome %v, err %v", b.seq, outcome, err)
	}
	if _, err := b.graph.Apply(t.Context(), b.world.Target.ID, rec.ID, snap); err != nil {
		t.Fatal(err)
	}
	notify.Movements(b.db.DB, slog.New(slog.NewTextHandler(io.Discard, nil)))(
		t.Context(), ingest.Stored{TargetID: b.world.Target.ID, ScanID: rec.ID})
}

// told is what one person is waiting on, of this kind.
func (b *build) told(t *testing.T, who *access.Account) []notify.Notification {
	t.Helper()
	subject := access.NewPerson(who.ID, who.Identity, false,
		map[int64][]access.Role{b.world.Product.ID: {access.PublicRead}}, 0)
	waiting, _, err := notify.NewStore(b.db.DB).Waiting(t.Context(), subject, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mine []notify.Notification
	for _, one := range waiting {
		if one.Kind == notify.InventoryMoved {
			mine = append(mine, one)
		}
	}
	return mine
}

// inventoryOf is that many names, each at the version given.
func inventoryOf(count int, version string) []string {
	names := make([]string, 0, count)
	for i := range count {
		names = append(names, fmt.Sprintf("dep%03d@%s", i, version))
	}
	return names
}

// moving is the same inventory with that many of its names at a new version.
func moving(names []string, count int) []string {
	next := make([]string, len(names))
	copy(next, names)
	for i := range count {
		next[i] = strings.Split(next[i], "@")[0] + "@2.0"
	}
	return next
}

func TestAnUploadThatChangedMuchOfABuildIsToldTo(t *testing.T) {
	eachBuild(t, func(t *testing.T, b *build) {
		held := inventoryOf(20, "1.0")
		b.holding(t, held...)

		// Half the inventory moves: ten of the twenty names go to a new
		// version. Past both the shipped share and the shipped floor.
		b.holding(t, moving(held, 10)...)

		told := b.told(t, b.reader)
		if len(told) != 1 {
			t.Fatalf("%d notifications, want one: %v", len(told), told)
		}
		if !strings.Contains(told[0].Body, "10 names moved in one upload, "+
			"against an inventory of 20") {
			t.Errorf("the message reads %q, want the count against the inventory", told[0].Body)
		}
		if !strings.Contains(told[0].Body, "0 arrived, 0 left, 10 at different versions") {
			t.Errorf("the message reads %q, want the three numbers behind it", told[0].Body)
		}
		// The link is the screen listing what moved, which is where the names
		// are: a message carrying the rows would be a list of a build's
		// contents in everybody's mail.
		if !strings.HasSuffix(told[0].Link, "/changes") ||
			!strings.Contains(told[0].Link, "/products/sonic/streams/master/variants/broadcom/scans/") {
			t.Errorf("the link is %q, want the listing for this upload", told[0].Link)
		}
		for _, name := range held {
			if strings.Contains(told[0].Body, strings.Split(name, "@")[0]) {
				t.Errorf("the message names %s: what moved is a screen, not a sentence", name)
			}
		}
	})
}

func TestAnOrdinaryNightIsToldToNobody(t *testing.T) {
	// The share, on its own. Twelve names of a hundred is past the shipped
	// floor of ten and under the shipped quarter, so the floor lets this
	// through and the share is what stops it. An alert every night is one
	// nobody reads.
	eachBuild(t, func(t *testing.T, b *build) {
		held := inventoryOf(100, "1.0")
		b.holding(t, held...)
		b.holding(t, moving(held, 12)...)

		if told := b.told(t, b.reader); len(told) != 0 {
			t.Errorf("an ordinary night said %v, want nothing", told)
		}
	})
}

func TestASmallInventoryIsNotReportedForMovingAFewNames(t *testing.T) {
	// The floor, on its own. Three of four names is three quarters of the
	// build, so the share lets this through and the floor is what stops it —
	// and three names is not what this exists to report.
	eachBuild(t, func(t *testing.T, b *build) {
		b.holding(t, "alpha@1.0", "beta@1.0", "gamma@1.0", "delta@1.0")
		b.holding(t, "alpha@2.0", "beta@2.0", "gamma@2.0", "delta@1.0")

		if told := b.told(t, b.reader); len(told) != 0 {
			t.Errorf("three names moving said %v, want nothing", told)
		}
	})
}

func TestTheDeploymentDecidesWhatItsShareIs(t *testing.T) {
	// The upload an ordinary night leaves alone, under a deployment that
	// wants a twentieth of a build reported. Only the share moves, so only
	// the share can be what let it through.
	eachBuild(t, func(t *testing.T, b *build) {
		if err := setting.NewStore(b.db.DB).Set(t.Context(), setting.DeltaShare, "5"); err != nil {
			t.Fatal(err)
		}

		held := inventoryOf(100, "1.0")
		b.holding(t, held...)
		b.holding(t, moving(held, 12)...)

		if told := b.told(t, b.reader); len(told) != 1 {
			t.Errorf("under a share of a twentieth, %d were told, want one", len(told))
		}
	})
}

func TestTheDeploymentDecidesWhatIsTooFewToMention(t *testing.T) {
	// The upload a small inventory leaves alone, under a deployment that
	// wants two names reported. Only the floor moves.
	eachBuild(t, func(t *testing.T, b *build) {
		if err := setting.NewStore(b.db.DB).Set(t.Context(), setting.DeltaFloor, "2"); err != nil {
			t.Fatal(err)
		}

		b.holding(t, "alpha@1.0", "beta@1.0", "gamma@1.0", "delta@1.0")
		b.holding(t, "alpha@2.0", "beta@2.0", "gamma@2.0", "delta@1.0")

		if told := b.told(t, b.reader); len(told) != 1 {
			t.Errorf("under a floor of two, %d were told, want one", len(told))
		}
	})
}

func TestTheFirstInventoryIsToldToNobody(t *testing.T) {
	// Every name in it is new. The first upload is the first picture of a
	// build rather than a change to one, and reported it would tell somebody
	// about every build the first time it is scanned.
	eachBuild(t, func(t *testing.T, b *build) {
		b.holding(t, inventoryOf(20, "1.0")...)

		if told := b.told(t, b.reader); len(told) != 0 {
			t.Errorf("the first upload said %v, want nothing", told)
		}
	})
}

func TestSomebodyWhoDoesNotReachTheProductIsNotTold(t *testing.T) {
	// The message names a build and what it holds, and the link answers only
	// for somebody who may read the product. Told to anybody else it is both
	// a disclosure and an alarm pointing at a refusal.
	eachBuild(t, func(t *testing.T, b *build) {
		held := inventoryOf(20, "1.0")
		b.holding(t, held...)
		b.holding(t, moving(held, 10)...)

		var waiting []notify.Notification
		stranger := access.NewPerson(b.watcher.ID, b.watcher.Identity, false, nil, 0)
		waiting, _, err := notify.NewStore(b.db.DB).Waiting(context.Background(), stranger, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 0 {
			t.Errorf("somebody holding nothing was told %v", waiting)
		}
	})
}
