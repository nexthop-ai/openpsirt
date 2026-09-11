package triage

import (
	"errors"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Who may read, argue about and agree to what.
//
// Every visibility rule this package enforces, in one file. They were spread
// through the proposal writer, which is where the first caller of each was:
// the file that decides whether somebody may see a decision is the file a
// reviewer checks REQ-42 and REQ-43 against, and scrolling past three hundred
// lines of write path to find it is how a rule gets checked once and then
// taken on trust.

// ErrNotTheirs is returned when somebody reaches for a decision about a
// product they may not triage.
//
// The same answer whether the product is one they cannot see or one they can
// only read: telling those apart would say which products exist to somebody
// who was told they may not ask.
var ErrNotTheirs = errors.New("not authorized")

// mayDecide is whether a subject may argue about findings of this visibility
// here, in the shape the narrowing rules take.
//
// A thin name over the subject's own answer, because the rules beside it are
// passed around as functions of this signature — and the rule itself lives on
// the subject, where every package asking it can reach one copy.
func mayDecide(subject access.Subject, productID int64, visibility access.Visibility) bool {
	return subject.Triages(visibility, productID)
}

// mayApprove reports whether a subject may agree to somebody else's claim.
//
// Approving is not deciding, and requiring the triage role for it made the
// approver capability decorative: somebody granted exactly the right to
// approve could not approve anything. It is a capability rather than a grant
// of visibility, so it is asked alongside whether they may read the finding —
// otherwise handing somebody the ability to approve hands them everything
// there is to approve.
//
// A triager may also approve, on somebody else's claim. Two triagers agreeing
// to each other's work is the ordinary shape of a small team, and the control
// that matters is that the two are different people — which is checked
// separately and has no override.
func mayApprove(subject access.Subject, productID int64, visibility access.Visibility) bool {
	if subject.Kind != access.Person {
		return false
	}
	if !subject.Reads(visibility, productID) {
		return false
	}
	return subject.Holds(access.Approver, productID) || mayDecide(subject, productID, visibility)
}

// mayTakePart reports whether a subject may add to a decision rather than only
// read it — writing a comment, or changing their own.
//
// This is what readable meant before the record readable at the finding's
// visibility widened reading to the finding's own visibility. Writing had
// leaned on the reading rule, so widening one widened the other, and a reader
// could comment on a decision they may not argue about. Named separately so
// the two cannot drift back together.
func mayTakePart(subject access.Subject, productID int64, visibility access.Visibility) bool {
	return mayApprove(subject, productID, visibility) || mayDecide(subject, productID, visibility)
}

// readable reports whether a subject may see what was decided.
//
// It is the finding's own visibility and nothing else — the same question
// readableFindings asks a few lines below, which is the point: a decision is
// part of the record of a finding, and who may read that record is who may
// read the finding.
//
// It asked whether the subject may decide or approve, and that was narrower
// than disclosure opening the record, which says the whole record — comments,
// decisions, actors — goes public when a private issue is disclosed. Under the
// old rule that was true only for people who could already see it: a reader
// holding private reading on a product opened a finding and was told none of
// its decisions existed, so they saw "deferred" with no way to see why or by
// whom, and the screen called the record was empty for anybody who is not a
// triager.
//
// Acting on any of it is unchanged. Arguing still asks for triage (mayDecide)
// and agreeing still asks for the approver capability (mayApprove); this
// widens reading alone.
func readable(subject access.Subject, productID int64, visibility access.Visibility) bool {
	if subject.Kind != access.Person {
		return false
	}
	return subject.Reads(visibility, productID)
}

// approvableBy narrows a query to the decisions a subject may agree to, which
// is a wider set than the ones they may argue about.
func approvableBy(query *bun.SelectQuery, subject access.Subject, column string) *bun.SelectQuery {
	// Deliberately without the cases. A collaborator may argue about the
	// issue they were brought in on and may not agree to anybody's claim
	// about it : two of them could otherwise satisfy the two people a
	// dismissal on an embargoed finding asks for, with nobody accountable
	// for the product involved.
	return narrowedBy(query, subject, column, mayApprove, withoutCases)
}

// readableBy narrows a query to the decisions a subject may see.
func readableBy(query *bun.SelectQuery, subject access.Subject, column string) *bun.SelectQuery {
	return narrowedBy(query, subject, column, readable, onCases)
}

// sortedKeys is the products of a case map in a settled order, so that two
// runs of the same query produce the same statement — which is what makes a
// prepared statement cache and a slow-query log worth reading.
func sortedKeys(cases map[int64][]int64) []int64 {
	out := make([]int64, 0, len(cases))
	for id := range cases {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// readableFindings narrows a query that joins findings to the ones a subject
// may read, per product: undisclosed findings where they read undisclosed
// findings on that product, disclosed ones everywhere else.
//
// The same rule as narrowedBy, asked of the finding's visibility and the
// product it sits in rather than the decision's. A decision somebody may read
// matches findings they may not, and a build name, a fix version or a count
// read off those is the disclosure — so every read that walks from a decision
// to its findings carries this.
//
// The finding's visibility is read through the given alias, and the product
// through the expression given — the stream's product where the read has
// joined that far, and the decision's where the match already requires the two
// to agree.
func readableFindings(query *bun.SelectQuery, subject access.Subject, finding, product string) *bun.SelectQuery {
	if subject.Kind != access.Person {
		return query.Where("1 = 0")
	}
	products, all := subject.Products()
	if all {
		return query
	}
	var private []int64
	for _, id := range products {
		if subject.Reads(access.Private, id) {
			private = append(private, id)
		}
	}
	if len(private) == 0 {
		return query.Where(finding+".visibility = ?", access.Public)
	}
	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.WhereOr(finding+".visibility = ?", access.Public).
			WhereOr(product+" IN (?)", bun.List(private))
	})
}

// onlyDecidable narrows a places query to what this subject may argue about.
//
// Written here rather than through narrowedBy because the product and the
// visibility sit on different tables in this statement — the product on the
// stream, the visibility on the finding — and narrowedBy takes one alias for
// both.
func onlyDecidable(query *bun.SelectQuery, subject access.Subject) *bun.SelectQuery {
	if subject.Kind != access.Person {
		return query.Where("1 = 0")
	}
	products, all := subject.Products()
	if all {
		return query
	}
	var private, public []int64
	for _, id := range products {
		switch {
		case mayDecide(subject, id, access.Private):
			private = append(private, id)
		case mayDecide(subject, id, access.Public):
			public = append(public, id)
		}
	}
	if len(private) == 0 && len(public) == 0 {
		return query.Where("1 = 0")
	}
	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		if len(private) > 0 {
			q = q.WhereOr("st.product_id IN (?)", bun.List(private))
		}
		if len(public) > 0 {
			q = q.WhereOr("st.product_id IN (?) AND f.visibility = ?",
				bun.List(public), access.Public)
		}
		return q
	})
}

// mayDecideOn is the same question about one named issue, which is what a
// collaborator was brought into.
//
// Separate from mayDecide rather than another argument to it, because the two
// are asked at different units: "may they decide in this product" is a
// question about a product and has no issue to name, and every caller that has
// one is arguing about that one issue.
//
// It never widens approving. mayApprove is built on mayDecide and stays there:
// two collaborators could otherwise satisfy the two people a dismissal on an
// embargoed finding asks for, with nobody accountable for the product.
func mayDecideOn(subject access.Subject, productID, vulnerabilityID int64,
	visibility access.Visibility) bool {

	return mayDecide(subject, productID, visibility) ||
		subject.OnCase(productID, vulnerabilityID)
}

// readableOn is readable with the case grant asked beside the product-wide
// question.
//
// The list narrowing already asks it, so a collaborator's own case appeared
// among the decisions and every route that reads one of them by identifier
// refused it: listed and then not there, which reads as a fault rather than as
// a rule. The grant is the pair of a product and an issue, so it needs the
// issue, which a row carries and a bare product-and-visibility rule cannot
// see.
func readableOn(subject access.Subject, productID, vulnerabilityID int64,
	visibility access.Visibility) bool {

	if readable(subject, productID, visibility) {
		return true
	}
	for _, may := range access.VisibleOn(subject, productID, vulnerabilityID) {
		if may == visibility {
			return true
		}
	}
	return false
}

// narrowedBy applies one of those rules as a condition on the query.
//
// Written as a condition rather than as filtering afterwards, because a count,
// an export or a report is exactly where filtering afterwards gets forgotten —
// and where the number is the leak even when no row is shown.
//
// Public and private are kept apart because they permit different things:
// reaching undisclosed findings implies reaching disclosed ones, and the
// reverse is exactly what must not happen. The rule is asked separately for
// each, per product, so a new right cannot widen one by being written into the
// other.
//
// The products are bound as values. They come from the subject's own grants
// rather than from anything typed, so writing them into the statement would be
// safe today and would be the shape somebody copies later when the list does
// come from outside. Whether a narrowing also lets through the cases somebody
// was brought into . Named rather than a bare boolean at two call sites,
// because which of the two a narrowing is decides whether a collaborator can
// approve.
const (
	onCases      = true
	withoutCases = false
)

func narrowedBy(query *bun.SelectQuery, subject access.Subject, column string,
	allowed func(access.Subject, int64, access.Visibility) bool, cases bool) *bun.SelectQuery {

	if subject.Kind != access.Person {
		return query.Where("1 = 0")
	}
	products, all := subject.Products()
	if all {
		return query
	}

	var private, public []int64
	for _, id := range products {
		switch {
		case allowed(subject, id, access.Private):
			private = append(private, id)
		case allowed(subject, id, access.Public):
			public = append(public, id)
		}
	}
	brought := map[int64][]int64{}
	if cases {
		for _, id := range subject.CaseProducts() {
			// Only where the product's own grant is not already wider. A case
			// adds nothing where somebody reads the product undisclosed, and
			// the narrower clause would be dead weight on every read.
			if !subject.Reads(access.Private, id) {
				brought[id] = subject.Cases(id)
			}
		}
	}
	if len(private) == 0 && len(public) == 0 && len(brought) == 0 {
		return query.Where("1 = 0")
	}

	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		if len(private) > 0 {
			q = q.WhereOr(column+".product_id IN (?)", bun.List(private))
		}
		if len(public) > 0 {
			q = q.WhereOr(column+".product_id IN (?) AND "+column+".visibility = ?",
				bun.List(public), access.Public)
		}
		// One issue in one product, which is what a collaborator was brought
		// into. Read from the subject rather than from anything typed, so the
		// pairs are the ones resolved at sign-in.
		for _, productID := range sortedKeys(brought) {
			q = q.WhereOr(column+".product_id = ? AND "+column+".vulnerability_id IN (?)",
				productID, bun.List(brought[productID]))
		}
		return q
	})
}
