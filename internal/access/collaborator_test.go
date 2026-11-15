// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// TestBringingSomebodyIntoACaseTwiceLeavesOneGrant pins the same idempotence
// for a case, and reads back what the row carries: who is on an embargoed
// case, and who put them there, are what is asked after a disclosure goes
// wrong.
func TestBringingSomebodyIntoACaseTwiceLeavesOneGrant(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		product := f.products["sonic"]
		person, err := f.store.Ensure(ctx, "ana", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		granter, err := f.store.Ensure(ctx, "bo", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-1", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-1"]

		for i := range 2 {
			if _, err := f.store.AddToCase(ctx, product, issue, person.ID, granter.ID); err != nil {
				t.Fatalf("bringing them in, attempt %d: %v", i+1, err)
			}
		}
		on, err := f.store.OnCase(ctx, product, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(on) != 1 || on[0] != person.ID {
			t.Errorf("the case carries %v, want the one person", on)
		}

		// And the row says who brought them in and when, which is what is
		// asked afterwards.
		rows, err := f.store.CaseRows(ctx, product, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the case has %d rows, want one", len(rows))
		}
		if rows[0].AddedBy != granter.ID || rows[0].AddedAt.IsZero() {
			t.Errorf("the grant does not say who made it or when: %+v", rows[0])
		}

		// Taken off, the grant stops and the record stays.
		if err := f.store.RemoveFromCase(ctx, product, issue, person.ID, granter.ID); err != nil {
			t.Fatal(err)
		}
		on, err = f.store.OnCase(ctx, product, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(on) != 0 {
			t.Errorf("somebody taken off the case is still on it: %v", on)
		}
		rows, err = f.store.CaseRows(ctx, product, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("CaseRows carries a withdrawn grant: %+v", rows)
		}
	})
}

func TestBringingSomebodyOntoACodeFindingTwiceLeavesOneGrant(t *testing.T) {
	// The second add finds the standing grant and reports it changed
	// nothing, rather than refusing or writing a second grant somebody is
	// told about twice.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		product := f.products["sonic"]
		person, err := f.store.Ensure(ctx, "ana", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		granter, err := f.store.Ensure(ctx, "bo", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		const occurrence = "clang-tidy/bugprone-use-after-move src/orch.cpp"
		for i, want := range []bool{true, false} {
			added, err := f.store.AddToCodeFinding(ctx, product, occurrence, person.ID, granter.ID)
			if err != nil || added != want {
				t.Fatalf("bringing them on, attempt %d, answered %v (%v), want %v", i+1, added, err, want)
			}
		}
		rows, err := f.store.CodeFindingRows(ctx, product, occurrence)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].PersonID != person.ID || rows[0].AddedBy != granter.ID {
			t.Fatalf("the code finding carries %+v, want one grant to them by the granter", rows)
		}

		if err := f.store.RemoveFromCodeFinding(ctx, product, occurrence, person.ID, granter.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
		if rows, err := f.store.CodeFindingRows(ctx, product, occurrence); err != nil || len(rows) != 0 {
			t.Errorf("taken off, the code finding carries %+v (%v)", rows, err)
		}
		if err := f.store.RemoveFromCodeFinding(ctx, product, occurrence, person.ID, granter.ID, time.Now()); !errors.Is(err, access.ErrNothingMatched) {
			t.Errorf("taking them off again answered %v, want nothing matched", err)
		}
	})
}

// A revocation that matched nothing is ErrNothingMatched, never success. The
// caller records a withdrawal on success, so answering one that did not
// happen writes a trail row for an act nobody performed.
func TestARevocationThatMatchedNothingSaysSo(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		product := f.products["sonic"]
		person, err := f.store.Ensure(ctx, "ana", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, product, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-1", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-1"]

		t.Run("a case they are not on", func(t *testing.T) {
			err := f.store.RemoveFromCase(ctx, product, issue, person.ID, person.ID)
			if !errors.Is(err, access.ErrNothingMatched) {
				t.Errorf("taking somebody off a case they were never on answered %v", err)
			}
		})
		t.Run("a token already revoked", func(t *testing.T) {
			token, _, err := f.store.NewToken(ctx, person.ID, "scripting", nil, nil, time.Hour, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.RevokeToken(ctx, token.ID); err != nil {
				t.Fatal(err)
			}
			if err := f.store.RevokeToken(ctx, token.ID); !errors.Is(err, access.ErrNothingMatched) {
				t.Errorf("revoking a revoked token answered %v", err)
			}
		})
		t.Run("a key already revoked", func(t *testing.T) {
			key, _, err := f.store.NewKey(ctx, "nightly", access.Scope{ProductID: product})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.Revoke(ctx, key.ID); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Revoke(ctx, key.ID); !errors.Is(err, access.ErrNothingMatched) {
				t.Errorf("revoking a revoked key answered %v", err)
			}
		})
	})
}
