// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// narrowed is the second person with triage on the first product and reading
// on the second.
func narrowed(f *fixture) access.Subject {
	return access.NewPerson(f.second.ID, f.second.Identity, false,
		map[int64][]access.Role{
			f.product:      {access.PublicRead, access.PrivateRead, access.PublicTriage, access.PrivateTriage},
			f.otherProduct: {access.PublicRead, access.PrivateRead},
		}, 0)
}

// Who may change what an advisory says is asked again when the change is
// taken again after a refused commit. A flaw named in another product in
// between puts the advisory into a document about that product, and somebody
// who triages only the first may no longer write it.
func TestAChangeTakenAgainAsksAgainWhoMayWriteTheAdvisory(t *testing.T) {
	for _, each := range []struct {
		name string
		act  func(f *fixture, as access.Subject, named, here, more string) error
	}{
		{"agreeing", func(f *fixture, as access.Subject, named, _, _ string) error {
			_, err := f.store.Approve(t.Context(), as, named, readEdition(t, f.store, f.who, named))
			return err
		}},
		{"retitling", func(f *fixture, as access.Subject, named, _, _ string) error {
			_, _, err := f.store.Retitle(t.Context(), as, named, "Retitled")
			return err
		}},
		{"naming a flaw", func(f *fixture, as access.Subject, named, _, more string) error {
			_, err := f.store.Add(t.Context(), as, named, "sonic", more)
			return err
		}},
		{"taking a flaw off", func(f *fixture, as access.Subject, named, here, _ string) error {
			return f.store.Drop(t.Context(), as, named, "sonic", here)
		}},
		{"taking back an agreement", func(f *fixture, as access.Subject, named, _, _ string) error {
			return f.store.Withdraw(t.Context(), as, named)
		}},
		{"marking a release", func(f *fixture, as access.Subject, named, here, _ string) error {
			return f.store.MarkAffected(t.Context(), as, named, "sonic", here, "master", "broadcom", true)
		}},
	} {
		t.Run(each.name, func(t *testing.T) {
			var between func()
			db, race := dbtest.Racing(t, func() { between() })
			f := made(t, fixtures.New(t, db))
			here := f.recorded(t, f.master)
			there := f.recorded(t, f.other)
			more := f.recorded(t, f.tagged)
			named := f.covering(t, [2]string{"sonic", here})
			between = func() {
				if _, err := advisory.NewStore(race.Other().DB).Add(t.Context(), f.who, named, "switchd", there); err != nil {
					t.Error(err)
				}
			}

			race.Arm(1)
			err := each.act(f, narrowed(f), named, here, more)
			if race.Unspent() != 0 {
				t.Fatal("the change committed nothing, so no attempt was taken again and this checks nothing")
			}
			if !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s, taken again after the advisory reached a product they only read, answered %v",
					each.name, err)
			}
		})
	}
}

// Whether there is anything to agree to, and whether the issue a release is
// marked against is on the advisory, are asked again when the change is taken
// again. The only flaw taken off in between leaves an advisory saying nothing,
// and a mark against an issue it no longer covers.
func TestAChangeTakenAgainAsksAgainWhatTheAdvisoryCovers(t *testing.T) {
	for _, each := range []struct {
		name string
		act  func(f *fixture, named, here string) error
		want error
	}{
		{"agreeing", func(f *fixture, named, _ string) error {
			_, err := f.store.Approve(t.Context(), f.approver, named, readEdition(t, f.store, f.who, named))
			return err
		}, advisory.ErrNothingToSay},
		{"marking a release", func(f *fixture, named, here string) error {
			return f.store.MarkAffected(t.Context(), f.approver, named, "sonic", here, "master", "broadcom", true)
		}, advisory.ErrNoSuchIssue},
	} {
		t.Run(each.name, func(t *testing.T) {
			var between func()
			db, race := dbtest.Racing(t, func() { between() })
			f := made(t, fixtures.New(t, db))
			here := f.recorded(t, f.master)
			named := f.covering(t, [2]string{"sonic", here})
			between = func() {
				if err := advisory.NewStore(race.Other().DB).Drop(t.Context(), f.who, named, "sonic", here); err != nil {
					t.Error(err)
				}
			}

			race.Arm(1)
			err := each.act(f, named, here)
			if race.Unspent() != 0 {
				t.Fatal("the change committed nothing, so no attempt was taken again and this checks nothing")
			}
			if !errors.Is(err, each.want) {
				t.Errorf("%s, taken again after the advisory's only flaw came off, answered %v, want %v",
					each.name, err, each.want)
			}
		})
	}
}

// A change to what an advisory says reads the advisory's edition before it
// asks who may write it. A flaw named in another product committing between
// the question and the write then takes the edition number the change is
// about to take, and the change, taken again, asks the question of what the
// advisory now covers. Read after the question, on an engine that reads what
// is committed at each statement, the number follows the rival's edition and
// the change lands for somebody who only reads the second product.
func TestAChangeRacingANewProductOnTheAdvisoryIsRefused(t *testing.T) {
	for _, each := range []struct {
		name string
		act  func(store *advisory.Store, as access.Subject, named, here, more string) error
	}{
		{"retitling", func(store *advisory.Store, as access.Subject, named, _, _ string) error {
			_, _, err := store.Retitle(t.Context(), as, named, "Retitled")
			return err
		}},
		{"naming a flaw", func(store *advisory.Store, as access.Subject, named, _, more string) error {
			_, err := store.Add(t.Context(), as, named, "sonic", more)
			return err
		}},
		{"taking a flaw off", func(store *advisory.Store, as access.Subject, named, here, _ string) error {
			return store.Drop(t.Context(), as, named, "sonic", here)
		}},
		{"marking a release", func(store *advisory.Store, as access.Subject, named, here, _ string) error {
			return store.MarkAffected(t.Context(), as, named, "sonic", here, "master", "broadcom", true)
		}},
	} {
		t.Run(each.name, func(t *testing.T) {
			fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
				f := made(t, w)
				here := f.recorded(t, f.master)
				there := f.recorded(t, f.other)
				more := f.recorded(t, f.tagged)
				named := f.covering(t, [2]string{"sonic", here})
				// The rival lands right after the transaction's own read of
				// what the advisory covers, which is the read deciding who
				// may write it.
				hooked, rival := dbtest.RivalAfterSelectInside(t, f.db, "advisory_issue", 5*time.Second,
					func() error {
						_, err := f.store.Add(context.Background(), f.who, named, "switchd", there)
						return err
					})
				err := each.act(advisory.NewStore(hooked), narrowed(f), named, here, more)
				if rivalErr := rival(); rivalErr != nil {
					t.Fatalf("the rival naming a flaw in the second product: %v", rivalErr)
				}
				if !errors.Is(err, access.ErrDenied) {
					t.Errorf("%s, racing a flaw named in a product they only read, answered %v",
						each.name, err)
				}
			})
		})
	}
}
