// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
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

// A declaration inside somebody else's transaction that loses the race says
// it lost, and the transaction around it takes the whole act again and finds
// what the other writer made. That is how the declare routes run: the store
// is handed the request's transaction, where the failed statement has already
// aborted it on one engine, and the error is passed through the route's
// refusal to the retry helper.
//
// The other writer lands between the declaration's read and its insert, every
// time, rather than when two goroutines happen to meet.
func TestADeclarationThatLosesItsRaceInsideATransactionIsTakenAgain(t *testing.T) {
	dbtest.Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		store := catalog.NewStore(db.DB)
		product, _, err := store.EnsureProduct(ctx, "mine", "Mine")
		if err != nil {
			t.Fatal(err)
		}
		quiet := slog.New(slog.DiscardHandler)
		for _, c := range []struct {
			table   string
			declare func(context.Context, *catalog.Store) error
		}{
			{"product", func(ctx context.Context, s *catalog.Store) error {
				_, _, err := s.EnsureProduct(ctx, "racing", "Racing")
				return err
			}},
			{"stream", func(ctx context.Context, s *catalog.Store) error {
				_, _, err := s.EnsureStream(ctx, product.ID, "raced", catalog.Branch, nil)
				return err
			}},
			{"variant", func(ctx context.Context, s *catalog.Store) error {
				_, _, err := s.EnsureVariant(ctx, product.ID, "raced", true)
				return err
			}},
		} {
			t.Run(c.table, func(t *testing.T) {
				hooked, rival := dbtest.RivalAfterRead(t, db, c.table, c.table, 5*time.Second, func() error {
					return c.declare(context.Background(), store)
				})
				attempts := 0
				err := database.InTransaction(ctx, hooked, func(ctx context.Context, tx bun.Tx) error {
					attempts++
					if err := c.declare(ctx, catalog.NewStore(tx)); err != nil {
						return core.DeclineDeclaration(quiet, err)
					}
					return nil
				})
				if err != nil {
					t.Errorf("a declaration that lost its race was refused: %v", err)
				}
				if err := rival(); err != nil {
					t.Errorf("the other declaration: %v", err)
				}
				if attempts < 2 {
					t.Errorf("the act ran %d times, so the race was never lost", attempts)
				}
			})
		}
	})
}

// Two declarations bringing one retired product back at once record one act:
// the one whose write lands second finds the product back already and says it
// restored nothing, so the trail reads one return to use and not two.
func TestTwoDeclarationsBringingOneProductBackRecordOneReturn(t *testing.T) {
	dbtest.Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		store := catalog.NewStore(db.DB)
		product, _, err := store.EnsureProduct(ctx, "retiring", "Retiring")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RetireProduct(ctx, product.ID); err != nil {
			t.Fatal(err)
		}
		var first catalog.Declared
		hooked, rival := dbtest.RivalAfterRead(t, db, "product", "product", 5*time.Second, func() error {
			var err error
			_, first, err = store.EnsureProduct(context.Background(), "retiring", "Retiring")
			return err
		})
		_, second, err := catalog.NewStore(hooked).EnsureProduct(ctx, "retiring", "Retiring")
		if err != nil {
			t.Fatal(err)
		}
		if err := rival(); err != nil {
			t.Fatal(err)
		}
		if first.Restored == second.Restored {
			t.Errorf("two declarations at once said restored %v and %v, want exactly one", first.Restored, second.Restored)
		}
	})
}
