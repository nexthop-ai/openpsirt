// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package rating is how a product's own rating of an issue is read in SQL.
//
// A leaf, and deliberately a small one. What a finding's severity *is* has one
// rule — the product's word where it has stated one, the published word
// otherwise — and the two packages that have to apply it cannot both own it:
// internal/finding imports internal/graph to walk a subtree, so internal/graph
// cannot import internal/finding to ask what a band is. A rule one side cannot
// say is a rule that side answers some other way, and a screen reading the
// published word while the list beside it reads the product's is two answers to
// one question.
//
// So the join and the two expressions live here, where neither side owns them
// and both may say them. The rating *row* does not: it is written and read
// through internal/finding, which is where a rating is proposed, agreed and
// put in force. What lives here is only the spelling a query needs.
package rating

import "sort"

// On is where a query finds the product it is asking about.
//
// The spellings are named rather than passed as text. A placeholder cannot
// bind a column name, so the product half of this join is spliced in — and a
// function taking a string would leave nothing between it and a column name
// arriving from a query parameter except that today's callers all pass a
// literal. Naming them is what makes that structural rather than a habit
// (REQ-66).
type On string

const (
	// OnStream is the product the row's stream belongs to, for a query that
	// spans products and reads each row's own.
	OnStream On = `"st"."product_id"`
	// OnDecision is the product a decision was recorded in.
	OnDecision On = `"de"."product_id"`
	// OnGrouped is the product column of a derived table aliased grouped,
	// for a query that reduces its findings to one row per issue and product
	// before the rating is joined.
	OnGrouped On = `"grouped"."product_id"`
	// OnPartial is the product the partial groups of the two-level form,
	// read as "f", carry.
	OnPartial On = `"f"."product_id"`
	// onBound is one product, bound. Used through Here.
	onBound On = "?"
)

// For is the left join that brings a product's own rating into a query that
// already joins vulnerability AS v.
//
// Left, because most issues are rated by nobody and those are the rows every
// list is mostly made of.
//
// A join rather than a column, because the rating is per product and an issue
// is one row for every product; the published word stays on the vulnerability
// every caller already joins.
func For(product On) string {
	return `LEFT JOIN "issue_rating" AS "ir" ON "ir"."vulnerability_id" = "v"."id"` +
		` AND "ir"."product_id" = ` + string(product)
}

// Here is For with the product bound.
//
// The same join rather than a second spelling of it: written out twice, a
// change to one is a change the other quietly does not make.
var Here = For(onBound)

// BandExpr is the rating a finding is judged by, folded to one of the four
// words that rank, as Fold folds it.
//
// Spelled once, and used by both the line and the deadline: the deadline
// treats an unrated issue as a medium, on the grounds that unknown is not
// harmless, and a line treating it as below everything drops it out of the
// working list and off any clock at once — 91,040 findings rated "unknown" on
// one real image. This product's where it has stated one, the published one
// otherwise: being able to say a published rating is wrong is pointless if
// everything that ranks and filters then ignores us.
//
// Read off the rating joined by For, so a query using this joins that too and
// says which product it is asking about. A statement that reads the expression
// without the join does not compile on any of the four engines, which is the
// failure being chosen — the alternative is a query that silently answers for
// the wrong product.
//
// Generated from the fold rather than written beside it, so the SQL and the Go
// cannot come to disagree about a word; a test evaluates it on every engine
// against Fold.
var BandExpr = func() string {
	words := make([]string, 0, len(folds))
	for word := range folds {
		words = append(words, word)
	}
	sort.Strings(words)
	said := "CASE " + EffectiveExpr
	for _, word := range words {
		if folds[word] != Unfolded {
			said += " WHEN '" + word + "' THEN '" + folds[word] + "'"
		}
	}
	return said + " ELSE '" + Unfolded + "' END"
}()

// Unfolded is the band a word folds to where the fold names no other: the
// middle one, because an unrated issue is unknown rather than harmless.
const Unfolded = "medium"

// folds is the band each recognized severity word falls in. The two words a
// scanner reports beneath low are answers, and they rank in the low band.
var folds = map[string]string{
	"critical":   "critical",
	"high":       "high",
	"medium":     "medium",
	"low":        "low",
	"negligible": "low",
	"none":       "low",
}

// Fold is the band a severity word falls in, and the middle band for a word
// the fold does not recognize, as BandExpr reads it.
func Fold(word string) string {
	band, _ := Folded(word)
	return band
}

// Folded is Fold, and whether the word is one the fold recognizes rather than
// one it puts in the middle band for being unknown.
func Folded(word string) (string, bool) {
	if band, ok := folds[word]; ok {
		return band, true
	}
	return Unfolded, false
}

// EffectiveExpr is the rating in force in one product, as a word.
const EffectiveExpr = `COALESCE("ir"."severity", "v"."severity", '')`
