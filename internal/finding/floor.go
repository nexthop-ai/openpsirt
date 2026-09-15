package finding

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// ranked is the severity words, least first. A line admits one of them and
// everything after it.
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
// either. They rank below every band, which is the same treatment a word
// nobody recognizes gets. What a line lets through is decided by Band rather
// than by the rank, and it folds them to medium.
func Recordable() []string {
	return append(Bands(), "negligible", "none")
}

// Ranks orders the four words for sorting, and for comparing one line against
// another, with anything unrecognized below all of them.
//
// Counted from one so that zero means unrecognized, which is the number the
// SQL expressions this mirrors also produce.
//
// No floor is enforced through this. What a line lets through goes through
// Band, which folds an unrated issue to medium rather than below everything —
// see BandExpr for why, and for what reading it the other way cost.
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
// rank alike everywhere, below every band (see Ranks above). Only what a
// reader saw differed, and it differed by screen: one row said "Unknown" and
// the row under it said "Unrated" about the same nothing.
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
// third place. This product's where it has stated one, the published one
// otherwise: being able to say a published rating is wrong is pointless if
// everything that ranks and filters then ignores us.
//
// Read off the rating joined by RatedFor, so a query using this joins that
// too and says which product it is asking about. A statement that reads the
// expression without the join does not compile on any of the four engines,
// which is the failure being chosen — the alternative is a query that silently
// answers for the wrong product.
const BandExpr = `CASE
	WHEN COALESCE(ir.severity, v.severity, '') = 'critical' THEN 'critical'
	WHEN COALESCE(ir.severity, v.severity, '') = 'high' THEN 'high'
	WHEN COALESCE(ir.severity, v.severity, '') IN ('low', 'negligible', 'none') THEN 'low'
	ELSE 'medium' END`

// EffectiveSeverityExpr is the rating in force in one product, as a word.
const EffectiveSeverityExpr = `COALESCE(ir.severity, v.severity, '')`

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
	// ProductID is whose line this is, and whose rating the line compares
	// against. Both halves belong to one product: the word is the product's
	// decision about what is worth an afternoon, and what it is compared to is
	// the product's own rating of the issue where it has made one.
	ProductID int64
}

// TriageFloors are the words a line may be set to, least first, with the word
// for no line at the head.
//
// One list rather than a copy per caller: what an operator may set and what
// the line is then compared against are the same vocabulary, and a second
// spelling of it is what let a word the line accepts be a word it cannot
// enforce.
func TriageFloors() []string {
	out := make([]string, 0, len(ranked)+1)
	return append(append(out, NoFloor), ranked...)
}

// FloorWord is a stored line as a word this understands, and whether it is one.
//
// Anything unrecognized answers NoFloor and false. A line that cannot be
// enforced has to read as no line at all: Hides was true for any word that was
// neither empty nor NoFloor, so a product set to something outside the
// vocabulary displayed a line everywhere while every query let everything
// through — the screens said a line was in force and nothing enforced one.
func FloorWord(word string) (string, bool) {
	matched := strings.ToLower(strings.TrimSpace(word))
	if matched == "" || matched == NoFloor {
		return NoFloor, true
	}
	for _, known := range ranked {
		if matched == known {
			return matched, true
		}
	}
	return NoFloor, false
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

// narrow keeps only what the line admits.
//
// Compared against the rating this product holds, which is its own where
// somebody there has made one and the published one otherwise — being able to
// say a published rating is wrong is pointless if the line then ignores us
// (the line a deployment triages at, a downgrade needing a second person). The
// line and the rating are both the product's, which is why the identifier
// travels with the word.
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
					q.NewSelect().TableExpr(`vulnerability AS "v"`).
						Join(RatedHere, f.ProductID).
						Column("v.id").
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
		TableExpr(`product AS "p"`).
		ColumnExpr("p.triage_floor").
		Where("p.id = ?", productID).
		Scan(ctx, &stated)
	if err != nil {
		return Floor{}, fmt.Errorf("read what this product triages: %w", err)
	}
	if stated.Floor != nil && *stated.Floor != "" {
		// Normalized here as well as refused at the write, so a value stored
		// by anything else reads as no line rather than as a line nothing
		// enforces.
		word, known := FloorWord(*stated.Floor)
		return Floor{Word: word, FromProduct: known, ProductID: productID}, nil
	}
	word, set, err := setting.NewStore(db).Get(ctx, setting.TriageFloor)
	if err != nil {
		return Floor{}, err
	}
	if !set || word == "" {
		return Floor{Word: NoFloor, ProductID: productID}, nil
	}
	line, _ := FloorWord(word)
	return Floor{Word: line, ProductID: productID}, nil
}
