package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Reach is how far a judgment travels, in the three parts somebody deciding
// needs told apart.
//
// The first two are consequences of the matching rules and are not choices —
// there is nothing to agree to, only something to be told. The third is the
// only choice, and it is the one worth slowing down for: ticking one is a
// claim about a version nobody has looked at.
//
// Presenting them as one number is what turns a considered judgment into a
// reflex, and it is also how a decision comes to reach builds the person
// making it never knew about.
type Reach struct {
	// Here is how many places in this build the judgment covers.
	Here int
	// Automatic are the other builds it reaches by matching: same upstream
	// versions, same chain. Nothing to tick.
	Automatic []Match
	// Differing hold the same issue at the same place at another version, so
	// each is asked separately.
	Differing []Match
}

// Match is the same issue at the same place in another build.
type Match struct {
	TargetID int64
	Stream   string
	Variant  string
	// Version is what that build ships under the name, which is what a route
	// naming a component resolves. For anything that is not a patched fork it
	// is the same as the upstream version below; for a fork it is the fork's
	// own, and the route knows nothing else.
	Version string
	// ComponentUpstream and ConsumerUpstream are what that build has. They are
	// why this is a separate question: where they are identical the decision
	// already applies there and nobody is asked, and where they differ it is a
	// different claim about different code.
	ComponentUpstream string
	ConsumerUpstream  string
	Places            int
	// Here says this is in the build being decided in — another version of the
	// same component, sitting beside the one in hand rather than in another
	// release or variant.
	Here bool
}

// Reaching finds the same issue at the same place held at a version this
// decision would not already cover.
//
// A decision is keyed on the combination of code rather than on the release it
// was made in, so anything running the same versions picks it up by looking it
// up — nothing is copied, nothing syncs, and nobody is asked. What this returns
// is the remainder: the same issue at the same place at *another version*, so
// the decision does not reach it and somebody has to say whether the same
// reasoning holds.
//
// **The build this is being decided in is searched too**, and that is the
// point. A build commonly ships one name at several versions — the reference
// image carries the Go standard library at four — so the same issue at the
// same place sits at versions right beside the one being decided. Looking only
// at other builds asked about a second variant's other version and said
// nothing about this build's, which reads as a question about variants when
// every question here is about a version.
//
// What is skipped is the decision itself: the rows in this build at the very
// versions being decided are what `at.Places` already counts.
//
// One place, answered by the read that takes many. The two were the same
// statement written out twice, differing by a column, a predicate and a group
// term — and only the many-place side had any coverage, so the one a route
// calls was the untested copy.
func (s *Store) Reaching(ctx context.Context, subject access.Subject, at Deciding,
	hereTargetID int64) (Reach, error) {

	return s.ReachingAcross(ctx, subject, []Deciding{at}, hereTargetID)
}

// ReachingAcross is Reaching for every place of one finding at once.
//
// The screen that asks this is deciding about an issue at a component, which
// is a group of places rather than one — a kernel flaw sits at sixty. Asking
// per place is a request each, so the screen sampled the first few and merged
// what came back; and because what it merges becomes the set of other builds
// offered to tick, a build reachable only from the ninth place was never
// offered and the judgment silently did not travel there. The sample was a
// cost control on the interface that had turned into a rule about what gets
// written.
//
// One query over every place answers it whole. Matches are merged across the
// places by the build and versions they name, because two places of one
// finding commonly land in the same other build and it is one thing to tick.
func (s *Store) ReachingAcross(ctx context.Context, subject access.Subject,
	places []Deciding, hereTargetID int64) (Reach, error) {

	if len(places) == 0 {
		return Reach{}, nil
	}
	merged := Reach{}
	// One index per list, because a build can be automatic for one place of
	// this finding and differing for another, and the two are different things
	// to say about it.
	seen := map[bool]map[string]int{true: {}, false: {}}
	add := func(into *[]Match, differing bool, match Match) {
		key := fmt.Sprintf("%d\x00%s\x00%s\x00%s", match.TargetID, match.Version,
			match.ComponentUpstream, match.ConsumerUpstream)
		if at, held := seen[differing][key]; held {
			// The same build reached from two places of this finding is one
			// thing somebody ticks, carrying the places of both.
			(*into)[at].Places += match.Places
			return
		}
		seen[differing][key] = len(*into)
		*into = append(*into, match)
	}
	// One statement over every place, which is what the paragraph above
	// promised and what a loop calling the single-place read did not do: the
	// screen deciding about a kernel flaw at sixty places issued sixty
	// grouped five-join queries and two authorization checks each, so the
	// cost the removed sampling was there to avoid came straight back.
	at := places[0]
	if !access.SeesOn(subject, at.ProductID, at.VulnerabilityID) {
		return Reach{}, access.Denied(fmt.Sprintf("read findings in product %d", at.ProductID))
	}
	visible := access.VisibleOn(subject, at.ProductID, at.VulnerabilityID)
	if len(visible) == 0 {
		return Reach{}, access.Denied(fmt.Sprintf("read findings in product %d", at.ProductID))
	}
	identities := make([]string, 0, len(places))
	// What each place is keyed on, which is what decides whether a build is
	// reached by matching or has to be ticked. Two places of one finding can
	// hold different versions, so the comparison is per place and cannot be
	// asked of the statement.
	keyed := make(map[string][2]string, len(places))
	for _, place := range places {
		merged.Here += place.Places
		identities = append(identities, place.PlaceIdentity)
		keyed[place.PlaceIdentity] = [2]string{place.ComponentUpstream, place.ConsumerUpstream}
	}

	var rows []struct {
		PlaceIdentity     string `bun:"place_identity"`
		TargetID          int64  `bun:"target_id"`
		Stream            string `bun:"stream"`
		Variant           string `bun:"variant"`
		Version           string `bun:"version"`
		ComponentUpstream string `bun:"component_upstream"`
		ConsumerUpstream  string `bun:"consumer_upstream"`
		Places            int    `bun:"places"`
	}
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON t.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = t.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = t.variant_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`st.display_name AS "stream"`).
		ColumnExpr(`va.display_name AS "variant"`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(ComponentUpstreamExpr+` AS "component_upstream"`).
		ColumnExpr(ConsumerUpstreamExpr+` AS "consumer_upstream"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		Where("st.product_id = ?", at.ProductID).
		Where("f.vulnerability_id = ?", at.VulnerabilityID).
		Where("f.place_identity IN (?)", bun.List(identities)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.place_identity, f.target_id, st.display_name, va.display_name, c.version, "+
			ComponentUpstreamExpr+", "+ConsumerUpstreamExpr).
		OrderExpr("st.display_name, va.display_name, c.version").
		Scan(ctx, &rows)
	if err != nil {
		return Reach{}, fmt.Errorf("look for the same issue elsewhere: %w", err)
	}

	for _, row := range rows {
		here, known := keyed[row.PlaceIdentity]
		if !known {
			continue
		}
		match := Match{
			TargetID: row.TargetID, Stream: row.Stream, Variant: row.Variant,
			Version:           row.Version,
			ComponentUpstream: row.ComponentUpstream, ConsumerUpstream: row.ConsumerUpstream,
			Places: row.Places,
			// Whether it is somewhere else or right here. A screen leads with
			// the version, because that is what differs, and says where as an
			// aside — but it still has to be able to say "here".
			Here: row.TargetID == hereTargetID,
		}
		if row.ComponentUpstream == here[0] && row.ConsumerUpstream == here[1] {
			// In this build at these versions, this *is* what is being
			// decided: the place count above already holds it, and listing it
			// as somewhere the judgment travels to would count it twice.
			if match.Here {
				continue
			}
			// Elsewhere at these versions the decision reaches it by matching,
			// so there is nothing to agree to — but somebody deciding should
			// still be told, because it is how far their judgment travels.
			add(&merged.Automatic, false, match)
			continue
		}
		add(&merged.Differing, true, match)
	}
	return merged, nil
}
