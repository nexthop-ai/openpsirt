// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
)

// issuedOver mints an advisory over the pairs given, has it agreed to and
// records that it went out, and answers its name.
func (f *fixture) issuedOver(t *testing.T, pairs ...[2]string) string {
	t.Helper()
	named := f.covering(t, pairs...)
	f.agreed(t, named)
	if _, err := f.store.Issued(t.Context(), f.who, issuer, named, "Went out"); err != nil {
		t.Fatalf("recording that %s went out: %v", named, err)
	}
	return named
}

// reaches is what one reader is shown of a set of advisories, asked through
// every read that narrows by the issues covered: the list, a read by name,
// the issuances of one, the report of what went out and the documents sent.
type reaches struct {
	listed, byName, issuances, published, sent map[string]bool
}

func (f *fixture) reachedBy(t *testing.T, subject access.Subject, names ...string) reaches {
	t.Helper()
	ctx := t.Context()
	out := reaches{
		listed: map[string]bool{}, byName: map[string]bool{}, issuances: map[string]bool{},
		published: map[string]bool{}, sent: map[string]bool{},
	}
	rows, _, err := f.store.List(ctx, subject, advisory.Covering{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		out.listed[row.Identifier] = true
	}
	for _, name := range names {
		_, _, err := f.store.Covers(ctx, subject, name)
		switch {
		case err == nil:
			out.byName[name] = true
		case !errors.Is(err, advisory.ErrNoSuchAdvisory):
			t.Fatalf("reading %s by name: %v", name, err)
		}
		gone, err := f.store.Issuances(ctx, subject, name)
		switch {
		case err == nil && len(gone) > 0:
			out.issuances[name] = true
		case err != nil && !errors.Is(err, advisory.ErrNoSuchAdvisory):
			t.Fatalf("reading what %s went out as: %v", name, err)
		}
	}
	went, err := f.store.Published(ctx, subject, nil, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range went {
		out.published[row.Advisory] = true
	}
	sent, err := f.store.Sent(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range sent {
		out.sent[row.Advisory] = true
	}
	return out
}

// expect checks one advisory against every read: shown by all of them where
// the reader reaches it, by none where they do not. A draft has no issuance,
// so the three reads of what went out are asked of issued advisories alone.
func (r reaches) expect(t *testing.T, who, what, name string, shown, issued bool) {
	t.Helper()
	reads := map[string]map[string]bool{"listed": r.listed, "read by name": r.byName}
	if issued {
		reads["shown as issued"] = r.issuances
		reads["reported as published"] = r.published
		reads["among the documents sent"] = r.sent
	}
	for read, got := range reads {
		if got[name] != shown {
			if shown {
				t.Errorf("%s was not %s an advisory about %s", read, who, what)
			} else {
				t.Errorf("an advisory about %s was %s to %s", what, read, who)
			}
		}
	}
}

func TestReadingUndisclosedWorkDoesNotReachAnAdvisoryAboutADisclosedFlaw(t *testing.T) {
	// Each visibility is its own grant. Somebody trusted with what has not
	// been disclosed in a product holds nothing on what has, so an advisory
	// about a disclosed flaw there is one they are told does not exist —
	// drafted or issued.
	each(t, func(t *testing.T, f *fixture) {
		draft := f.covering(t, [2]string{"sonic", f.disclosed(t, f.master)})
		issued := f.issuedOver(t, [2]string{"sonic", f.disclosed(t, f.tagged)})

		privately := access.NewPerson(f.second.ID, f.second.Identity, false,
			map[int64][]access.Role{f.product: {access.PrivateRead}}, 0)
		got := f.reachedBy(t, privately, draft, issued)
		got.expect(t, "a private reader", "a disclosed flaw, drafted", draft, false, false)
		got.expect(t, "a private reader", "a disclosed flaw, issued", issued, false, true)

		// A public reader of the same product reaches both, so the refusal
		// above is the visibility and not the fixture.
		publicly := access.NewPerson(f.second.ID, f.second.Identity, false,
			map[int64][]access.Role{f.product: {access.PublicRead}}, 0)
		got = f.reachedBy(t, publicly, draft, issued)
		got.expect(t, "a public reader", "a disclosed flaw, drafted", draft, true, false)
		got.expect(t, "a public reader", "a disclosed flaw, issued", issued, true, true)
	})
}

func TestAnAdvisoryIsReadAtTheVisibilityHeldInItsOwnProduct(t *testing.T) {
	// Reading undisclosed work in one product and disclosed work in another
	// reads each kind in its own product and neither kind in both. A union
	// across products reads disclosed work in the first as though the grant
	// on the second reached it.
	each(t, func(t *testing.T, f *fixture) {
		disclosedHere := f.issuedOver(t, [2]string{"sonic", f.disclosed(t, f.master)})
		undisclosedHere := f.issuedOver(t, [2]string{"sonic", f.recorded(t, f.tagged)})
		disclosedThere := f.issuedOver(t, [2]string{"switchd", f.disclosed(t, f.other)})
		undisclosedThere := f.issuedOver(t, [2]string{"switchd", f.recorded(t, f.other)})
		draftHere := f.covering(t, [2]string{"sonic", f.disclosed(t, f.older)})
		draftThere := f.covering(t, [2]string{"switchd", f.disclosed(t, f.other)})

		mixed := access.NewPerson(f.second.ID, f.second.Identity, false,
			map[int64][]access.Role{
				f.product:      {access.PrivateRead},
				f.otherProduct: {access.PublicRead},
			}, 0)
		got := f.reachedBy(t, mixed, disclosedHere, undisclosedHere, disclosedThere,
			undisclosedThere, draftHere, draftThere)
		const who = "a private reader of sonic and public reader of switchd"
		got.expect(t, who, "a disclosed flaw in sonic", disclosedHere, false, true)
		got.expect(t, who, "an undisclosed flaw in sonic", undisclosedHere, true, true)
		got.expect(t, who, "a disclosed flaw in switchd", disclosedThere, true, true)
		got.expect(t, who, "an undisclosed flaw in switchd", undisclosedThere, false, true)
		got.expect(t, who, "a disclosed flaw in sonic, drafted", draftHere, false, false)
		got.expect(t, who, "a disclosed flaw in switchd, drafted", draftThere, true, false)
	})
}
