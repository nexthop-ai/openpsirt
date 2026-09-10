package finding

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Ranked severities, least first. A line admits this word and everything after
// it.
//
// The one list. It was three — this, an identical one beside the sort keys, and
// a switch statement written twice in two packages — and three copies of an
// ordering is three chances for a word added to one of them to be missing from
// the others, which shows up as a rating that sorts one way and filters
// another.
var ranked = []string{"low", "medium", "high", "critical"}

// Bands is the four rated words, worst first — the order a report reads in and
// the order a person looks for.
//
// Returned as a copy, because a caller ranging over the package's own slice
// can sort it. The four appeared under seven names across the tree, and three
// of those were this order written out by hand.
func Bands() []string {
	out := make([]string, 0, len(ranked))
	for i := len(ranked) - 1; i >= 0; i-- {
		out = append(out, ranked[i])
	}
	return out
}

// Recordable is every severity word somebody may type, worst first.
//
// Wider than the four bands by the two a scanner reports and nobody ranks:
// "negligible" and "none" are answers, and a person recording a flaw may give
// either — they rank below every band and so survive no floor, which is the
// same treatment a word nobody recognizes gets.
func Recordable() []string {
	return append(Bands(), "negligible", "none")
}

// Ranks orders the words, least first, with anything unrecognized below all of
// them.
//
// A word outside the list — "negligible", "unknown", whatever a producer
// invents — ranks below every one of them and so survives no floor at all.
// That is deliberate: a floor is a claim about how bad something is, and a
// rating nobody recognizes is not evidence of anything.
//
// Counted from one so that zero means unrecognized, which is the number the
// SQL expressions this mirrors also produce.
func Ranks(word string) int {
	for i, known := range ranked {
		if strings.EqualFold(word, known) {
			return i + 1
		}
	}
	return 0
}

// Unrated is what a rating nobody recognizes is called, and what a rating
// nobody gave is called: they are the same state.
//
// A scanner's own "unknown", a producer's invented word, and no word at all
// rank alike everywhere — below every band, surviving no floor (see Ranks
// above). Only what a reader saw differed, and it differed by screen: one row
// said "Unknown" and the row under it said "Unrated" about the same nothing.
const Unrated = "unrated"

// BandOf is what to call a rating when it is being counted or shown.
//
// One of the four where it is one of the four, and Unrated otherwise. Named
// here beside the ordering rather than derived at each place that groups by
// severity, because three copies of "which words are real" is three chances
// for one of them to grow a fifth.
func BandOf(word string) string {
	if Ranks(word) == 0 {
		return Unrated
	}
	return strings.ToLower(strings.TrimSpace(word))
}

// BandExpr is the rating a finding is judged by, folded to one of the four
// words that rank.
//
// Spelled once, and used by both the line and the deadline, because they were
// briefly two rules reading the same fact and they disagreed: the deadline
// treats an unrated issue as a medium, on the grounds that unknown is not
// harmless, while the line was treating it as below everything. On a real
// image that was **91,040 findings rated "unknown"** dropping out of the
// working list *and* off any clock, which is the opposite of what an unknown
// rating should cause. Every bug in this project's identity and expiry rules
// came from letting one fact into two rules; this is that lesson arriving in a
// third place. Ours where we have stated one, the published one otherwise:
// being able to say a published rating is wrong is pointless if everything
// that ranks and filters then ignores us.
const BandExpr = `CASE
	WHEN COALESCE(v.assessed_severity, v.severity, '') = 'critical' THEN 'critical'
	WHEN COALESCE(v.assessed_severity, v.severity, '') = 'high' THEN 'high'
	WHEN COALESCE(v.assessed_severity, v.severity, '') IN ('low', 'negligible', 'none') THEN 'low'
	ELSE 'medium' END`

// EffectiveSeverityExpr is the rating in force, as a word.
const EffectiveSeverityExpr = `COALESCE(v.assessed_severity, v.severity, '')`

// Band folds a severity word the same way BandExpr does.
func Band(severity string) string {
	switch severity {
	case "critical", "high":
		return severity
	case "low", "negligible", "none":
		return "low"
	default:
		return "medium"
	}
}

// NoFloor is the line that hides nothing, and what a deployment starts with. A
// tool that quietly kept findings out of the list on the day it was installed
// would be deciding something nobody asked it to.
const NoFloor = "everything"

// Floor is what is worth triaging here.
//
// Five thousand findings is a list nobody reads, and the ones that drown it
// are the ones nobody was ever going to act on. Below the line a finding is
// still recorded, still counted and still reportable — it leaves the working
// list, not the system.
type Floor struct {
	// Word is the least severity worth triaging, or NoFloor.
	Word string
	// FromProduct says the product stated this rather than inheriting the
	// deployment's line. Carried so a screen can say whose decision it is
	// looking at, which is the difference between a number somebody chose and
	// one nobody noticed.
	FromProduct bool
}

// Hides reports whether the line keeps anything out at all.
func (f Floor) Hides() bool { return f.Word != "" && f.Word != NoFloor }

// admits returns the severity words this line lets through, or nil where it
// lets through everything.
func (f Floor) admits() []string {
	if !f.Hides() {
		return nil
	}
	for i, word := range ranked {
		if word == f.Word {
			return ranked[i:]
		}
	}
	return nil
}

// narrow keeps only what the line admits, on a query that joins vulnerability
// AS v.
//
// Compared against the rating the deployment holds, which is ours where we
// have made one and the published one otherwise — being able to say a
// published rating is wrong is pointless if the line then ignores us (the line
// a deployment triages at, a downgrade needing a second person).
func (f Floor) narrow(q *bun.SelectQuery) *bun.SelectQuery {
	if words := f.admits(); len(words) > 0 {
		// Never below the line if somebody is using it. A line is a
		// claim about how bad something has to be before it is worth
		// an afternoon, and being exploited is not a claim about how
		// bad it is — it is a fact about the world, and it is the one
		// thing that cannot be set aside on a rating. Hiding a
		// known-exploited finding because it was rated low is the
		// failure this whole line is supposed to prevent, arrived at
		// from the other side.
		//
		// Both halves read without joining the issue: exploitation off
		// the urgency, whose top band is exactly that (Ranked.Rank),
		// and the rating as a membership test against the issues the
		// line admits. So a query this narrows can stay on finding's
		// covering index.
		q = q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr("f.urgency >= ?", int64(exploitedBand)).
				WhereOr("f.vulnerability_id IN (?)",
					q.NewSelect().TableExpr("vulnerability AS v").Column("v.id").
						Where(BandExpr+" IN (?)", bun.List(words)))
		})
	}
	return q
}

// Admits reports whether the line lets this through.
func (f Floor) Admits(exploited bool, severity string) bool {
	words := f.admits()
	if len(words) == 0 || exploited {
		return true
	}
	band := Band(severity)
	for _, word := range words {
		if word == band {
			return true
		}
	}
	return false
}

// FloorFor reads the line in force for one product.
//
// The product's own where it has stated one, the deployment's otherwise. A
// product with no opinion inherits rather than copying, so it keeps following
// the deployment when the deployment changes its mind.
func FloorFor(ctx context.Context, db bun.IDB, productID int64) (Floor, error) {
	var stated struct {
		Floor *string `bun:"triage_floor"`
	}
	err := db.NewSelect().
		TableExpr("product AS p").
		ColumnExpr("p.triage_floor").
		Where("p.id = ?", productID).
		Scan(ctx, &stated)
	if err != nil {
		return Floor{}, fmt.Errorf("read what this product triages: %w", err)
	}
	if stated.Floor != nil && *stated.Floor != "" {
		return Floor{Word: *stated.Floor, FromProduct: true}, nil
	}
	word, set, err := setting.NewStore(db).Get(ctx, setting.TriageFloor)
	if err != nil {
		return Floor{}, err
	}
	if !set || word == "" {
		return Floor{Word: NoFloor}, nil
	}
	return Floor{Word: word}, nil
}
