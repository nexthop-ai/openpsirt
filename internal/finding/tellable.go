package finding

import (
	"context"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// The people who may be told that an issue exists.
//
// Separate from any one act on an issue because several ask the same question
// and each answered it differently before: a rating, a finding's detail, a
// decision about a place, a disclosure date, a fix target, an assignment. What
// they share is that the name in the path is a name somebody may have guessed,
// and answering "that is not yours" differently from "there is no such thing"
// turns any of those routes into a way to count what is being kept quiet.
//
// All of them are asked of a named product, because every one of these acts is
// about an issue somewhere rather than about an issue at large.

// ErrUnknownIssue is returned where an issue is not one this subject may be
// told about, and is answered exactly as a name nobody has ever used.
var ErrUnknownIssue = errors.New("no issue is known by that name")

// MayBeToldOfIn reports whether this subject may be told an issue exists in
// one product.
//
// The one question, because every act on an issue here is about it in a named
// product: a rating, a finding's detail, a decision about a place, a
// disclosure date, a fix target, an assignment. A second form asking
// "anywhere" reads "an issue is public knowledge" one product wider than it
// needs to.
//
// The question every route shaped "this issue, at this place" has to ask
// before it answers anything at all. Those routes resolve the issue name first
// and check the finding's visibility afterwards, so a name somebody holds and
// a name nobody holds came back differently — which is exactly what
// authorizing before resolving a name forbids, applied to issues rather than
// to people. Worse, the check that came second was not always a refusal: a fix
// target answered an empty list and an assignment answered "done" while
// writing nothing, so two routes disclosed by succeeding.
//
// Narrowed to the product because these routes are already about one. An issue
// that reaches this product only where the reader may not look is, for them,
// an issue this product does not have.
//
// Read through the finding rather than the issue because visibility lives on
// the finding: the same issue is undisclosed in one product and announced in
// another, and what the reader may be told follows the place.
//
// There is no exemption here for an issue that reaches nothing. A route about
// a place has no answer to give when the issue is not at one, and the caller
// was going to be refused anyway — the point here is that it is refused in the
// same words as a name nobody has used. Recording a rating is the one act that
// wants the exemption, and it asks for it separately (mayRateHere).
func (s *Store) MayBeToldOfIn(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) (bool, error) {

	return MayBeToldOfWithin(ctx, s.db, subject, productID, vulnerabilityID)
}

// MayBeToldOfWithin is MayBeToldOfIn against a handle the caller chooses, so
// that a transaction asks it from inside itself.
//
// A retry re-runs its closure against a database that has moved, so an
// authorization answered outside describes a world that is gone.
func MayBeToldOfWithin(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, vulnerabilityID int64) (bool, error) {

	if subject.Kind != access.Person {
		return false, nil
	}
	// One issue in one product is a grant of its own, and it is asked
	// before the product-wide question: a collaborator does not see the
	// product at any visibility, which is the whole of what the grant is
	// for.
	if subject.OnCase(productID, vulnerabilityID) {
		return sitsIn(ctx, db, productID, vulnerabilityID)
	}
	if !subject.Sees(productID) {
		return false, nil
	}
	products, all := subject.Products()
	held, err := onlyReadable(db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("st.product_id = ?", productID),
		subject, products, all).Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read where this issue sits here: %w", err)
	}
	return held > 0, nil
}

// sitsIn says this issue is open somewhere in this product, without asking who
// is looking.
//
// The narrowing a collaborator's grant replaces, not one it skips: the pair
// they were brought in on is the whole of what they may reach, so the only
// question left is whether the issue is there at all — and answering "no such
// finding" for one that is not keeps a case grant from confirming an issue
// exists in a product it does not.
func sitsIn(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (bool, error) {
	here, err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("f.id").
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("st.product_id = ?", productID).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read where this issue sits here: %w", err)
	}
	return here, nil
}
