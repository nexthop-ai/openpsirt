// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

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
				if _, err := f.store.Add(t.Context(), f.who, named, "switchd", there); err != nil {
					t.Error(err)
				}
			}
			// Triage on the first product, reading on the second.
			narrowed := access.NewPerson(f.second.ID, f.second.Identity, false,
				map[int64][]access.Role{
					f.product:      {access.PublicRead, access.PrivateRead, access.PublicTriage, access.PrivateTriage},
					f.otherProduct: {access.PublicRead, access.PrivateRead},
				}, 0)

			race.Arm(1)
			err := each.act(f, narrowed, named, here, more)
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
