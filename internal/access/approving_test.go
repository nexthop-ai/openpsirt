// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// TestTheApprovingConditionAnswersAsTheApprovingRule holds the statement a
// query asks "may this person agree today" by to the rule a signed-in subject
// is asked by: every role alone and every pair of roles, granted on the
// product or across every product, at every visibility, somebody deactivated,
// and an administrator granted nothing.
func TestTheApprovingConditionAnswersAsTheApprovingRule(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		sonic := f.products["sonic"]
		roles := access.Roles()
		var sets [][]access.Role
		for i := range roles {
			sets = append(sets, []access.Role{roles[i]})
			for j := i + 1; j < len(roles); j++ {
				sets = append(sets, []access.Role{roles[i], roles[j]})
			}
		}

		// ask is the statement's answer for one person on sonic at one
		// visibility.
		ask := func(personID int64, v access.Visibility) bool {
			t.Helper()
			cond, args := access.MayApproveWhere(`"p"."id"`, `"pd"."id"`, `'`+string(v)+`'`)
			n, err := f.db.NewSelect().
				TableExpr(`"person" AS "p"`).
				Join(`CROSS JOIN "product" AS "pd"`).
				Where(`"p"."id" = ?`, personID).
				Where(`"pd"."id" = ?`, sonic).
				Where(cond, args...).Count(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return n > 0
		}
		// rule is the Go rule's answer, for the subject as it resolves.
		rule := func(identity string, v access.Visibility) bool {
			t.Helper()
			subject, err := f.store.Resolve(ctx, identity)
			if err != nil {
				return false
			}
			return access.MayApprove(v, subject.Holds(access.Approver, sonic),
				subject.Reads(v, sonic), subject.Triages(v, sonic))
		}

		examined, approving := 0, 0
		for n, set := range sets {
			for _, estate := range []bool{false, true} {
				identity := fmt.Sprintf("person-%d-%v", n, estate)
				person, err := f.store.Ensure(ctx, identity, identity, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, role := range set {
					if estate {
						err = f.store.GrantEstateRole(ctx, person.ID, role)
					} else {
						err = f.store.GrantRole(ctx, person.ID, sonic, role)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				for _, v := range access.Visibilities() {
					want := rule(identity, v)
					if got := ask(person.ID, v); got != want {
						t.Errorf("holding %v (across every product: %v) at %s: the statement says %v, the rule %v",
							set, estate, v, got, want)
					}
					examined++
					if want {
						approving++
					}
				}
			}
		}
		if examined == 0 || approving == 0 || approving == examined {
			t.Fatalf("%d of %d cases approve, so the comparison separated nothing", approving, examined)
		}

		// Somebody who left keeps the grants that made them an approver.
		departed := holding(t, f, "departed", "Departed", sonic, access.Approver, access.PrivateRead)
		if _, err := f.store.Deactivate(ctx, departed.ID); err != nil {
			t.Fatal(err)
		}
		for _, v := range access.Visibilities() {
			if got, want := ask(departed.ID, v), rule("departed", v); got || want {
				t.Errorf("somebody deactivated may approve at %s: the statement says %v, the rule %v", v, got, want)
			}
		}

		admin, err := f.store.Ensure(ctx, "admin", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range access.Visibilities() {
			if ask(admin.ID, v) {
				t.Errorf("an administrator granted nothing may approve at %s", v)
			}
		}
	})
}

// TestAnInactiveGrantIsNoRightToApprove pins the grant left in place by a
// change of mode: kept so the change can be undone, and granting nothing.
func TestAnInactiveGrantIsNoRightToApprove(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		sonic := f.products["sonic"]
		person := holding(t, f, "alice", "Alice", sonic, access.Approver, access.PrivateRead)
		if err := f.store.GrantEstateRole(ctx, person.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		approves := func() (bool, bool) {
			t.Helper()
			var answers [2]bool
			for i, v := range []access.Visibility{access.Private, access.Public} {
				cond, args := access.MayApproveWhere(`"p"."id"`, `"pd"."id"`, `'`+string(v)+`'`)
				n, err := f.db.NewSelect().TableExpr(`"person" AS "p"`).
					Join(`CROSS JOIN "product" AS "pd"`).
					Where(`"p"."id" = ?`, person.ID).
					Where(`"pd"."id" = ?`, sonic).
					Where(cond, args...).Count(ctx)
				if err != nil {
					t.Fatal(err)
				}
				answers[i] = n > 0
			}
			return answers[0], answers[1]
		}
		if private, public := approves(); !private || !public {
			t.Fatalf("live grants do not approve: private %v, public %v", private, public)
		}
		if err := f.store.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}
		if private, public := approves(); private || public {
			t.Errorf("inactive grants still approve: private %v, public %v", private, public)
		}
	})
}
