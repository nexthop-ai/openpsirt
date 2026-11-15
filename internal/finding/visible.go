// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// onlyReadable narrows a query to what one person may read: the products they
// hold anything on, and within those, the visibilities they read in each.
//
// Both halves, together. The visibility half is written per product and
// admits nothing in a product the asker holds nothing on; the product half
// states that bound outright.
//
// The product half is not always this one, which is why the visibility half
// is callable on its own. A query that has already pinned a single product —
// a build's readiness, one product's releases — has narrowed further than this
// would, and applying a set membership over it would be a second clause saying
// less. Those call inOneProduct, which is the same pairing stated for the case
// where the query brought its own first half. Nothing calls the visibility
// half bare: that is the thing to check when reading one of these, and it is
// the reason the two names exist rather than one function and a comment.
func onlyReadable(q *bun.SelectQuery, subject access.Subject, products []int64, all bool) *bun.SelectQuery {
	if !all {
		q = q.Where(`"st"."product_id" IN (?)`, bun.List(products))
	}
	return onlyVisible(q, subject, products, all)
}

// inOneProduct narrows to what may be read inside a product the query has
// already pinned itself to.
//
// The pairing onlyReadable makes, for a query whose first half is an equality
// rather than a set: it says out loud that the product half has been done,
// which a bare call to the visibility half does not.
func inOneProduct(q *bun.SelectQuery, subject access.Subject, productID int64,
	all bool) *bun.SelectQuery {

	return onlyVisible(q, subject, []int64{productID}, all)
}

// onlyVisible narrows a query to what this subject may read, per product.
//
// Each visibility is its own grant on each product: reading undisclosed
// findings on one product does not make them visible on another, and does not
// make the disclosed ones visible anywhere.
//
// An administrator is not narrowed at all, and the shape makes that easy to
// get backwards: Products() reports "everything" as an empty list with a flag,
// and an empty list rendered as IN (NULL) is never true — so the clause
// collapses to public-only for the one subject who is supposed to see
// everything, and their dashboard, deadline list and trend all under-report
// with nothing saying so.
func onlyVisible(q *bun.SelectQuery, subject access.Subject, products []int64, all bool) *bun.SelectQuery {
	if all {
		return q
	}
	readings := access.Split(products, subject.Reads)
	where, args := access.VisibleWhere(`"st"."product_id"`, `"f"."visibility"`, readings)
	return q.Where(where, args...)
}

// orCarried narrows a query to what this subject may read, or to a disclosed
// row they or a team of theirs hold.
//
// The "what am I dealing with" list alone asks it. An assignment carries a
// disclosed row to whoever holds it, whatever they read: that is what gives a
// bare capability content, and a disclosed finding handed to somebody who
// reads only undisclosed work is theirs to see. An undisclosed row carries no
// further than private reading does. Every other list, count and export
// answers a question about a product, and holding one row in it is not an
// answer to that.
func orCarried(q *bun.SelectQuery, subject access.Subject, products []int64, all bool) *bun.SelectQuery {
	if all {
		return q
	}
	readings := access.Split(products, subject.Reads)
	where, args := access.VisibleWhere(`"st"."product_id"`, `"f"."visibility"`, readings)
	if mine := subject.Mine(); len(mine) > 0 {
		where = "(" + where + ` OR ("f"."assigned_to" IN (?) AND "f"."visibility" = ?))`
		args = append(args, bun.List(mine), access.Public)
	}
	return q.Where(where, args...)
}
