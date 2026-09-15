package catalog_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// TestDeclaringTheSameThingTwiceAtOnceSucceedsBothTimes pins the contract the
// declare routes publish: "all three are idempotent: declaring what is already
// there succeeds and changes nothing, because a pipeline that has to know
// whether it is the first one is not usable from CI".
//
// It was true sequentially and false concurrently. Each path reads, finds
// nothing, and inserts, with a unique index as the only arbiter — so two
// pipelines that start together both find nothing, both insert, and the loser
// is handed a constraint violation. Nothing coordinates CI pipelines, which
// makes the concurrent case the ordinary one rather than the exotic one.
//
// Every engine, because what is under test is what each one does to the second
// writer and they do not agree: the error type differs, and on a cluster the
// refusal can arrive at COMMIT rather than at the insert.
func TestDeclaringTheSameThingTwiceAtOnceSucceedsBothTimes(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)
		ctx := t.Context()
		store := catalog.NewStore(db.DB)

		product, _, err := store.EnsureProduct(ctx, "mine", "Mine")
		if err != nil {
			t.Fatal(err)
		}

		// Both halves of a declaration, and the pair a scan is filed against.
		for _, c := range []struct {
			what string
			race func() error
		}{
			{"a product", func() error {
				_, _, err := store.EnsureProduct(ctx, "racing", "Racing")
				return err
			}},
			{"a branch", func() error {
				_, _, err := store.EnsureStream(ctx, product.ID, "raced", catalog.Branch, nil)
				return err
			}},
			{"a variant", func() error {
				_, _, err := store.EnsureVariant(ctx, product.ID, "raced", true)
				return err
			}},
		} {
			// Two at once, which is two CI pipelines cutting the same branch.
			var wait sync.WaitGroup
			failures := make([]error, 2)
			wait.Add(2)
			for i := range failures {
				go func() {
					defer wait.Done()
					failures[i] = c.race()
				}()
			}
			wait.Wait()
			for i, err := range failures {
				if err != nil {
					t.Errorf("declaring %s twice at once: caller %d was refused: %v",
						c.what, i+1, err)
				}
			}
		}

		// And the build a scan is filed against, which is the upload path and
		// the one a pipeline reaches without declaring anything.
		stream, err := store.StreamByName(ctx, product.ID, "raced")
		if err != nil {
			t.Fatal(err)
		}
		variant, err := store.VariantByName(ctx, product.ID, "raced")
		if err != nil {
			t.Fatal(err)
		}
		var wait sync.WaitGroup
		targets := make([]*catalog.Target, 2)
		failures := make([]error, 2)
		wait.Add(2)
		for i := range targets {
			go func() {
				defer wait.Done()
				targets[i], failures[i] = store.TargetFor(ctx, stream.ID, variant.ID)
			}()
		}
		wait.Wait()
		for i, err := range failures {
			if err != nil {
				t.Fatalf("filing the first scan for one build twice at once: "+
					"caller %d was refused: %v", i+1, err)
			}
		}
		// And they agree about which build it is. Two rows would be two
		// histories for one thing somebody ships.
		if targets[0].ID != targets[1].ID {
			t.Errorf("one build was recorded as two: %d and %d",
				targets[0].ID, targets[1].ID)
		}
	})
}

// TestDeclaringSomethingElseUnderAKnownNameIsStillRefused is the other half:
// making the race succeed must not make a contradiction succeed.
func TestDeclaringSomethingElseUnderAKnownNameIsStillRefused(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)
		ctx := t.Context()
		store := catalog.NewStore(db.DB)

		product, _, err := store.EnsureProduct(ctx, "mine", "Mine")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.EnsureStream(ctx, product.ID, "master", catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.EnsureStream(ctx, product.ID, "master", catalog.Tag, nil); !errors.Is(err, catalog.ErrDiffers) {
			t.Errorf("a branch redeclared as a tag answered %v", err)
		}
		if _, _, err := store.EnsureProduct(ctx, "mine", "Something Else"); !errors.Is(err, catalog.ErrDiffers) {
			t.Errorf("a product redeclared with another display name answered %v", err)
		}
	})
}
