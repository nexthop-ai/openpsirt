package finding

import (
	"context"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Who may be told that an issue exists.
//
// Separate from any one act on an issue because several ask the same question
// and each answered it differently before: a rating, a finding's detail, a
// decision about a place, a disclosure date, a fix target, an assignment. What
// they share is that the name in the path is a name somebody may have guessed,
// and answering "that is not yours" differently from "there is no such thing"
// turns any of those routes into a way to count what is being kept quiet.

// ErrUnknownIssue is returned where an issue is not one this subject may be
// told about, and is answered exactly as a name nobody has ever used.
var ErrUnknownIssue = errors.New("no issue is known by that name")

// mayBeToldOf reports whether this subject may be told an issue exists.
//
// An assessment is a claim about an issue rather than about a place, which is
// why making one asks for triage on some product rather than on a particular
// one. Both of those read "an issue is public knowledge" — which holds for a
// CVE and does not hold for an identifier this deployment minted for a flaw
// nobody has announced. Naming one and being handed the severity recorded
// against it is a disclosure, and it does not stop being one because the route
// taken to it was a rating.
//
// So an issue somebody may read a finding of, in any product, is one they may
// argue about. An issue that reaches nothing here is nobody's secret — a CVE
// interned by a scan that no longer matches anything, or one rated before it
// arrives — and refusing that would take away the half of an opinion recorded
// against the issue that reaches products an issue has not met yet. A flaw
// recorded here always sits at a build, so it is never in that second case.
//
// Read through the finding rather than the issue because visibility lives on
// the finding: the same issue is undisclosed in one product and announced in
// another, and what the reader may be told follows the place.
func mayBeToldOf(ctx context.Context, db bun.IDB, subject access.Subject,
	vulnerabilityID int64) (bool, error) {

	if subject.Kind != access.Person {
		return false, nil
	}
	products, all := subject.Products()
	if all {
		return true, nil
	}
	// Closed findings count. An issue whose findings have all been fixed is
	// still one the reader has seen, and dropping it here would quietly retire
	// their ability to argue about it.
	readable, err := onlyReadable(db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Where("f.vulnerability_id = ?", vulnerabilityID),
		subject, products, all).Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read where this issue sits: %w", err)
	}
	if readable > 0 {
		return true, nil
	}
	anywhere, err := db.NewSelect().Model((*Finding)(nil)).
		Where("vulnerability_id = ?", vulnerabilityID).Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether this issue reaches anything: %w", err)
	}
	return anywhere == 0, nil
}

// MayBeToldOfIn reports whether this subject may be told an issue exists in
// one product.
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
// Unlike mayBeToldOf there is no exemption for an issue that reaches nothing.
// A route about a place has no answer to give when the issue is not at one,
// and the caller was going to be refused anyway — the point here is that it is
// refused in the same words as a name nobody has used.
func (s *Store) MayBeToldOfIn(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) (bool, error) {

	if subject.Kind != access.Person {
		return false, nil
	}
	// One issue in one product is a grant of its own, and it is asked
	// before the product-wide question: a collaborator does not see the
	// product at any visibility, which is the whole of what the grant is
	// for.
	if subject.OnCase(productID, vulnerabilityID) {
		return s.sitsIn(ctx, productID, vulnerabilityID)
	}
	if !subject.Sees(productID) {
		return false, nil
	}
	products, all := subject.Products()
	held, err := onlyReadable(s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
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
func (s *Store) sitsIn(ctx context.Context, productID, vulnerabilityID int64) (bool, error) {
	here, err := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		ColumnExpr("f.id").
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("st.product_id = ?", productID).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read where this issue sits here: %w", err)
	}
	return here, nil
}
