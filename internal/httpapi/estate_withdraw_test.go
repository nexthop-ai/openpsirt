package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Withdrawing a role held across the estate hands back the work it was holding.
//
// It is the last role in every product at once, so somebody whose only role
// came from it keeps every finding assigned to them: out of the shared queue
// because it is assigned, and out of theirs because they can no longer open it.
// The per-product withdrawal has released work for exactly this reason since it
// was written; this one did not, and nothing said so either way.
func TestWithdrawingAnEstateRoleHandsBackWhatItWasHolding(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		seedTheirs(t, r)

		holder, err := r.rights.Ensure(ctx, "estate-triager", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.Claim(ctx, holder.ID, "estate-triager"); err != nil {
			t.Fatal(err)
		}
		if err := r.rights.GrantEstateRole(ctx, holder.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}

		// Assigned by writing the column rather than through the assignment
		// endpoint: what is being tested is the withdrawal, and standing up an
		// assigner with reach into this product would test that path instead.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("assigned_to = ?", holder.PartyID).
			Where("closed_at IS NULL").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		var before int
		if err := r.db.DB.NewSelect().Table("finding").ColumnExpr("COUNT(*)").
			Where("assigned_to = ?", holder.PartyID).Scan(ctx, &before); err != nil {
			t.Fatal(err)
		}
		if before == 0 {
			t.Fatal("nothing was assigned, so the release has nothing to prove")
		}

		got := asPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/estate-triager/roles/private-triage", "")
		if got.Code != http.StatusOK {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Released int64 `json:"released"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if out.Released != int64(before) {
			t.Errorf("reported %d handed back, not the %d that were assigned", out.Released, before)
		}

		var after int
		if err := r.db.DB.NewSelect().Table("finding").ColumnExpr("COUNT(*)").
			Where("assigned_to = ?", holder.PartyID).Scan(ctx, &after); err != nil {
			t.Fatal(err)
		}
		if after != 0 {
			t.Errorf("%d findings are still assigned to somebody who cannot open them", after)
		}

		// And the grant itself is gone, rather than merely stopped counting.
		left, err := r.rights.EstateGrants(ctx, holder.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) != 0 {
			t.Errorf("withdrawing left %d rows behind", len(left))
		}
	})
}

// It does not touch a role held against a named product. Those are
// withdrawn one at a time through the path that names the product, and work in
// a product where they still hold something stays with them.
func TestWithdrawingAnEstateRoleLeavesNamedProductsAlone(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		seedTheirs(t, r)

		holder, err := r.rights.Ensure(ctx, "both-ways", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.Claim(ctx, holder.ID, "both-ways"); err != nil {
			t.Fatal(err)
		}
		if err := r.rights.GrantEstateRole(ctx, holder.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		theirs, err := r.rights.ByIdentity(ctx, "both-ways")
		if err != nil {
			t.Fatal(err)
		}
		// Held in its own right on the product the findings sit in, so the
		// estate grant going is not their last role there.
		var productID int64
		if err := r.db.DB.NewSelect().Table("product").Column("id").
			Where("name = ?", "theirs").Scan(ctx, &productID); err != nil {
			t.Fatal(err)
		}
		if err := r.rights.GrantRole(ctx, theirs.ID, productID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("assigned_to = ?", holder.PartyID).
			Where("closed_at IS NULL").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		got := asPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/both-ways/roles/private-triage", "")
		if got.Code != http.StatusOK {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
		}

		var still int
		if err := r.db.DB.NewSelect().Table("finding").ColumnExpr("COUNT(*)").
			Where("assigned_to = ?", holder.PartyID).Scan(ctx, &still); err != nil {
			t.Fatal(err)
		}
		if still == 0 {
			t.Error("work was handed back in a product where they still hold a role")
		}
		held, err := r.rights.Grants(ctx, theirs.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 1 {
			t.Errorf("the per-product grant was disturbed: %+v", held)
		}
	})
}
