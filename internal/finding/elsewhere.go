// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// Reach is how far a decision travels, in the three parts somebody deciding
// needs told apart.
//
// The first two are consequences of the matching rules and are not choices —
// there is nothing to agree to, only something to be told. The third is the
// only choice, and it is the one worth slowing down for: ticking one is a
// claim about a version nobody has looked at.
//
// Presenting them as one number is what turns a considered decision into a
// reflex, and it is also how a decision comes to reach builds the person
// making it never knew about.
type Reach struct {
	// Here is how many occurrences in this build the decision covers.
	Here int
	// Automatic are the other builds it reaches by matching: same upstream
	// versions, same chain. Nothing to tick.
	Automatic []Match
	// Differing hold the same issue at the same occurrence at another version, so
	// each is asked separately.
	Differing []Match
}

// Match is the same issue at the same occurrence in another build.
type Match struct {
	BuildID     int64
	BranchOrTag string
	Variant     string
	// BranchOrTagName and VariantName are the names they are shown under; the
	// two above are the names a path addresses them by.
	BranchOrTagName, VariantName string
	// Version is what that build ships under the name, which is what a route
	// naming a component resolves. For anything that is not a patched fork it
	// is the same as the upstream version below; for a fork it is the fork's
	// own, and the route knows nothing else.
	Version string
	// ComponentUpstream and ConsumerUpstream are what that build has. They are
	// why this is a separate question: where they are identical the decision
	// already applies there and nobody is asked, and where they differ it is a
	// different decision about different code.
	ComponentUpstream string
	ConsumerUpstream  string
	Occurrences       int
	// Here says this is in the build being decided in — another version of the
	// same component, sitting beside the one in hand rather than in another
	// release or variant.
	Here bool
}

// Reaching finds the same issue at the same occurrence held at a version this
// decision would not already cover.
//
// A decision is keyed on the combination of code rather than on the release it
// was made in, so anything running the same versions picks it up by looking it
// up — nothing is copied, nothing syncs, and nobody is asked. What this returns
// is the remainder: the same issue at the same occurrence at *another version*,
// so the decision does not reach it and somebody has to say whether the same
// reasoning holds.
//
// The build this is being decided in is searched too, and that is the point. A
// build commonly ships one name at several versions — the reference image
// carries the Go standard library at four — so the same issue at the same
// occurrence sits at versions right beside the one being decided. Looking only
// at other builds asked about a second variant's other version and said nothing
// about this build's, which reads as a question about variants when every
// question here is about a version.
//
// The decision itself is skipped: the rows in this build at the very
// versions being decided are what `at.Occurrences` already counts.
//
// One occurrence, answered by the read that takes many. The two were the same
// statement written out twice, differing by a column, a predicate and a group
// term — and only the many-occurrence side had any coverage, so the one a route
// calls was the untested copy.
func (s *Store) Reaching(ctx context.Context, subject access.Subject, at Deciding,
	hereBuildID int64) (Reach, error) {

	return s.ReachingAcross(ctx, subject, []Deciding{at}, hereBuildID)
}

// ReachingAcross is Reaching for every occurrence of one finding at once.
//
// The screen that asks this is deciding about an issue at a component, which
// is a group of occurrences rather than one — a kernel flaw sits at sixty. What
// it answers becomes the set of other builds offered to tick, so it covers
// every occurrence: a build reachable only from the ninth occurrence is offered
// like any other, and a sample of the occurrences would be a rule about where a
// decision travels.
//
// One query over every occurrence answers it whole. Matches are merged across
// the occurrences by the build and versions they name, because two occurrences
// of one finding commonly land in the same other build and it is one thing to
// tick.
func (s *Store) ReachingAcross(ctx context.Context, subject access.Subject,
	occurrences []Deciding, hereBuildID int64) (Reach, error) {

	if len(occurrences) == 0 {
		return Reach{}, nil
	}
	merged := Reach{}
	// One index per list, because a build can be automatic for one occurrence of
	// this finding and differing for another, and the two are different things
	// to say about it.
	seen := map[bool]map[string]int{true: {}, false: {}}
	// The test for two rows being the same entry, which is not the same
	// question for the two lists.
	//
	// A build the decision already reaches is one thing to be told about,
	// however many occurrences of this finding reach it: keyed on anything
	// finer, a kernel flaw at sixty occurrences listed the same other build
	// sixty times, once per consumer that pulls the package in — which is a
	// screen saying "and sixty other builds" about one.
	//
	// A build holding it at *another* version is a separate decision, because
	// the code differs — so the version keys it, and nothing below the version
	// does: two consumers pulling in the same version there is still one
	// version to decide about.
	add := func(into *[]Match, differing bool, match Match) {
		key := fmt.Sprintf("%d", match.BuildID)
		if differing {
			key += "\x00" + match.Version
		}
		if at, held := seen[differing][key]; held {
			// The same build reached from two occurrences of this finding is
			// one thing somebody ticks, carrying the occurrences of both.
			(*into)[at].Occurrences += match.Occurrences
			return
		}
		seen[differing][key] = len(*into)
		*into = append(*into, match)
	}
	// One statement over every occurrence. A loop over the single-occurrence
	// read is sixty grouped five-join queries and two authorization checks
	// each for a kernel flaw at sixty occurrences.
	at := occurrences[0]
	visible, err := access.ReadableOn(subject, at.ProductID, at.VulnerabilityID)
	if err != nil {
		return Reach{}, err
	}
	identities := make([]string, 0, len(occurrences))
	// The key of each occurrence, which decides whether a build is reached by
	// matching or has to be ticked. Two occurrences of one finding can hold
	// different versions, so the comparison is per occurrence and cannot be
	// asked of the statement.
	keyed := make(map[string][2]string, len(occurrences))
	for _, occurrence := range occurrences {
		merged.Here += occurrence.Occurrences
		identities = append(identities, occurrence.OccurrenceIdentity)
		keyed[occurrence.OccurrenceIdentity] = [2]string{occurrence.ComponentUpstream, occurrence.ConsumerUpstream}
	}

	var rows []struct {
		OccurrenceIdentity string `bun:"occurrence_identity"`
		BuildID            int64  `bun:"build_id"`
		BranchOrTag        string `bun:"branch_or_tag"`
		BranchOrTagName    string `bun:"branch_or_tag_name"`
		Variant            string `bun:"variant"`
		VariantName        string `bun:"variant_name"`
		Version            string `bun:"version"`
		ComponentUpstream  string `bun:"component_upstream"`
		ConsumerUpstream   string `bun:"consumer_upstream"`
		Occurrences        int    `bun:"places"`
	}
	kinds, kindArgs := kind.VersionCarry.Where(`"f"."kind"`)
	err = s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Where(kinds, kindArgs...).
		Join(`JOIN "build" AS "t" ON "t"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "t"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		ColumnExpr(`"f"."occurrence_identity" AS "occurrence_identity"`).
		ColumnExpr(`"f"."build_id" AS "build_id"`).
		ColumnExpr(`"st"."name" AS "branch_or_tag"`).
		ColumnExpr(catalog.ShownExpr("st")+` AS "branch_or_tag_name"`).
		ColumnExpr(`"va"."name" AS "variant"`).
		ColumnExpr(catalog.ShownExpr("va")+` AS "variant_name"`).
		ColumnExpr(`"c"."version" AS "version"`).
		ColumnExpr(ComponentUpstreamExpr+` AS "component_upstream"`).
		ColumnExpr(ConsumerUpstreamExpr+` AS "consumer_upstream"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		Where(`"st"."product_id" = ?`, at.ProductID).
		Where(`"f"."vulnerability_id" = ?`, at.VulnerabilityID).
		Where(`"f"."occurrence_identity" IN (?)`, bun.List(identities)).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		GroupExpr(`"f"."occurrence_identity", "f"."build_id", "st"."name", "st"."display_name", "va"."name", "va"."display_name", `+
			`"c"."version", `+
			ComponentUpstreamExpr+", "+ConsumerUpstreamExpr).
		OrderExpr(`"st"."name", "va"."name", "c"."version"`).
		Scan(ctx, &rows)
	if err != nil {
		return Reach{}, fmt.Errorf("look for the same issue elsewhere: %w", err)
	}

	for _, row := range rows {
		here, known := keyed[row.OccurrenceIdentity]
		if !known {
			continue
		}
		match := Match{
			BuildID: row.BuildID, BranchOrTag: row.BranchOrTag, Variant: row.Variant,
			BranchOrTagName: row.BranchOrTagName, VariantName: row.VariantName,
			Version:           row.Version,
			ComponentUpstream: row.ComponentUpstream, ConsumerUpstream: row.ConsumerUpstream,
			Occurrences: row.Occurrences,
			// Its place, elsewhere or right here. A screen code findings with
			// the version, because that is what differs, and says where as an
			// aside — but it still has to be able to say "here".
			Here: row.BuildID == hereBuildID,
		}
		if row.ComponentUpstream == here[0] && row.ConsumerUpstream == here[1] {
			// In this build at these versions, this *is* what is being
			// decided: the occurrence count above already holds it, and listing
			// it as somewhere the decision travels to would count it twice.
			if match.Here {
				continue
			}
			// Elsewhere at these versions the decision reaches it by matching,
			// so there is nothing to agree to — but somebody deciding should
			// still be told, because it is how far their decision travels.
			add(&merged.Automatic, false, match)
			continue
		}
		add(&merged.Differing, true, match)
	}
	return merged, nil
}
