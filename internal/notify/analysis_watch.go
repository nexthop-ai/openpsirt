// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// The bounds on when a series has gone quiet on a build.
const (
	// quietRuns is how many applied runs a series needs on a build before its
	// rhythm is a thing to measure. Two runs are one gap, which is a guess.
	quietRuns = 3
	// quietGaps is how many of the newest gaps the rhythm is read from, so a
	// pipeline that moved from weekly to nightly is judged by what it does
	// now.
	quietGaps = 10
	// quietTimes is how many usual gaps make one silence.
	quietTimes = 3
	// quietFloor is the shortest silence worth saying. A pipeline running
	// hourly that misses three runs is a bad afternoon rather than a
	// pipeline nobody is watching.
	quietFloor = 24 * time.Hour
)

// analysisBuild is one series on one build in use, with the names a message
// needs.
type analysisBuild struct {
	ProductID     int64  `bun:"product_id"`
	BranchOrTagID int64  `bun:"branch_or_tag_id"`
	SeriesID      int64  `bun:"series_id"`
	BuildID       int64  `bun:"build_id"`
	Product       string `bun:"product"`
	BranchOrTag   string `bun:"branch_or_tag"`
	Variant       string `bun:"variant"`
	// The same three as an address names them.
	ProductName     string `bun:"product_name"`
	BranchOrTagName string `bun:"branch_or_tag_name"`
	VariantName     string `bun:"variant_name"`
	Series          string `bun:"series"`
	Folded          string `bun:"series_folded"`
}

// analysisRuns is the applied runs of analyzer series against builds still in
// use, joined to the names a message needs. The caller adds what narrows it.
func analysisRuns(db bun.IDB) *bun.SelectQuery {
	return db.NewSelect().
		TableExpr(`"series_run" AS "sr"`).
		Join(`JOIN "series" AS "se" ON "se"."id" = "sr"."series_id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "sr"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "st"."product_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"st"."id" AS "branch_or_tag_id"`).
		ColumnExpr(`"sr"."series_id" AS "series_id"`).
		ColumnExpr(`"sr"."build_id" AS "build_id"`).
		ColumnExpr(`"p"."display_name" AS "product"`).
		ColumnExpr(`"st"."display_name" AS "branch_or_tag"`).
		ColumnExpr(`"va"."display_name" AS "variant"`).
		ColumnExpr(`"p"."name" AS "product_name"`).
		ColumnExpr(`"st"."name" AS "branch_or_tag_name"`).
		ColumnExpr(`"va"."name" AS "variant_name"`).
		ColumnExpr(`"se"."name" AS "series"`).
		ColumnExpr(`"se"."name_folded" AS "series_folded"`).
		Where(`"se"."kind" = ?`, kind.Analysis).
		Where(`"sr"."status" = ?`, series.Applied).
		// A build out of use is analyzed by nobody on purpose.
		Where(`"p"."retired_at" IS NULL`).
		Where(`"st"."retired_at" IS NULL`).
		Where(`"va"."retired_at" IS NULL`)
}

// pastEndOfLife is the releases past their end of life, whose builds are
// left alone on purpose for the reason a retired one is.
func (w *sweep) pastEndOfLife(ctx context.Context) (map[int64]bool, error) {
	ended, err := catalog.NewStore(w.db).BranchesAndTagsPastEndOfLife(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	past := make(map[int64]bool, len(ended))
	for _, id := range ended {
		past[id] = true
	}
	return past, nil
}

// tellSecurityTesting hands a condition to everybody who reads the product's
// security testing findings. What it names is a series and a build, and both are
// about security testing work.
func (w *sweep) tellSecurityTesting(out map[int64][]Holds, productID int64, holds Holds) {
	holds.Private, holds.SecurityTesting = true, true
	holds.ProductID = &productID
	for personID, per := range w.reach {
		if per[productID].readsSecurityTesting {
			out[personID] = append(out[personID], holds)
		}
	}
}

// analysesNotComparable is every series whose newest run on a build could not
// be compared, against the product's security testing readers.
//
// While it holds, nothing that series stops reporting on that build is marked
// no longer detected, so a fix and a broken pipeline look the same. It clears on
// the next comparable run.
func (w *sweep) analysesNotComparable(ctx context.Context) (map[int64][]Holds, error) {
	var rows []struct {
		analysisBuild
		Reason series.Reason `bun:"reason"`
	}
	err := analysisRuns(w.db).
		ColumnExpr(`"sr"."not_comparable" AS "reason"`).
		Where(`"sr"."comparable" = ?`, false).
		// The newest applied run, in the order the applier reads them.
		Where(`NOT EXISTS (SELECT 1 FROM "series_run" AS "nw" `+
			`WHERE "nw"."series_id" = "sr"."series_id" AND "nw"."build_id" = "sr"."build_id" `+
			`AND "nw"."status" = ? AND ("nw"."built_at" > "sr"."built_at" `+
			`OR ("nw"."built_at" = "sr"."built_at" AND "nw"."id" > "sr"."id")))`, series.Applied).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which analyzer runs could not be compared: %w", err)
	}
	past, err := w.pastEndOfLife(ctx)
	if err != nil {
		return nil, err
	}

	out, err := w.everybody(ctx, SecurityTestingNotComparable)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if past[row.BranchOrTagID] {
			continue
		}
		w.tellSecurityTesting(out, row.ProductID, Holds{
			About: identify("security-testing-not-comparable", strconv.FormatInt(row.SeriesID, 10),
				strconv.FormatInt(row.BuildID, 10)),
			Body: fmt.Sprintf("%s %s %s: the last run of %s could not be compared, because %s. "+
				"Nothing it stops reporting is marked no longer detected until a run can be.",
				row.Product, row.BranchOrTag, row.Variant, row.Series, uncomparable(row.Reason)),
			Link: weblink.CodeFindings(row.ProductName, row.BranchOrTagName, row.VariantName, "", ""),
		})
	}
	return out, nil
}

// uncomparable puts a reason a run could not be compared into words.
func uncomparable(r series.Reason) string {
	switch r {
	case series.ExitStatus:
		return "the analyzer exited with an error"
	case series.Incomplete:
		return "the analyzer said it did not finish"
	case series.FailureSignal:
		return "the analyzer reported a failure of its own run"
	case series.NoCoverage:
		return "the run states neither what it analyzed nor which rules it ran"
	case series.UnitsShort:
		return "it analyzed less than it was meant to"
	case series.ToolChanged:
		return "the analyzer's version changed"
	case series.RulesChanged:
		return "the rules it ran changed"
	}
	return "of " + string(r)
}

// analysesQuiet is every series that has stopped arriving on a build it ran
// on regularly, against the product's security testing readers.
//
// Measured against the series' own rhythm on that build: three times its
// usual gap, and never less than a day. A series with fewer than three runs
// there has no rhythm yet and is never quiet. It clears on the next run.
func (w *sweep) analysesQuiet(ctx context.Context) (map[int64][]Holds, error) {
	var rows []struct {
		analysisBuild
		ReceivedAt time.Time `bun:"received_at"`
		Newest     int       `bun:"newest"`
	}
	// The newest runs of each series on each build, numbered newest first, so
	// the rhythm is read from the same few runs however long the series has
	// run.
	err := w.db.NewSelect().
		TableExpr(`(?) AS "ranked"`, analysisRuns(w.db).
			ColumnExpr(`"sr"."received_at" AS "received_at"`).
			ColumnExpr(`ROW_NUMBER() OVER (PARTITION BY "sr"."series_id", "sr"."build_id" `+
				`ORDER BY "sr"."received_at" DESC, "sr"."id" DESC) AS "newest"`)).
		ColumnExpr(`"ranked".*`).
		Where(`"ranked"."newest" <= ?`, quietGaps+1).
		OrderExpr(`"ranked"."series_id", "ranked"."build_id", "ranked"."received_at" DESC`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read when each analyzer series last arrived: %w", err)
	}

	type pair struct{ series, build int64 }
	var order []pair
	runs := make(map[pair][]time.Time)
	named := make(map[pair]analysisBuild)
	for _, row := range rows {
		at := pair{row.SeriesID, row.BuildID}
		if _, seen := named[at]; !seen {
			order = append(order, at)
			named[at] = row.analysisBuild
		}
		runs[at] = append(runs[at], row.ReceivedAt.UTC())
	}
	past, err := w.pastEndOfLife(ctx)
	if err != nil {
		return nil, err
	}

	out, err := w.everybody(ctx, SecurityTestingStopped)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for _, at := range order {
		build := named[at]
		if past[build.BranchOrTagID] {
			continue
		}
		silent, quiet := quietFor(runs[at], now)
		if !quiet {
			continue
		}
		body := fmt.Sprintf("%s %s %s: no run of %s has been applied for %s.",
			build.Product, build.BranchOrTag, build.Variant, build.Series, plainly(int(silent.Hours()/24)))
		turned, err := w.lastRefused(ctx, build, runs[at][0])
		if err != nil {
			return nil, err
		}
		if turned != nil {
			body = fmt.Sprintf("%s %s %s: no run of %s has been applied for %s, and an upload "+
				"of it was turned away on %s: %s", build.Product, build.BranchOrTag, build.Variant,
				build.Series, plainly(int(silent.Hours()/24)), day(turned.At), turned.Reason)
		}
		w.tellSecurityTesting(out, build.ProductID, Holds{
			About: identify("security-testing-stopped", strconv.FormatInt(at.series, 10),
				strconv.FormatInt(at.build, 10)),
			Body: body,
			Link: weblink.CodeFindings(build.ProductName, build.BranchOrTagName, build.VariantName, "", ""),
		})
	}
	return out, nil
}

// quietFor is how long a series has been silent and whether that is longer
// than its rhythm allows. arrived is newest first.
func quietFor(arrived []time.Time, now time.Time) (time.Duration, bool) {
	if len(arrived) < quietRuns {
		return 0, false
	}
	gaps := make([]time.Duration, 0, len(arrived)-1)
	for i := 1; i < len(arrived); i++ {
		gaps = append(gaps, arrived[i-1].Sub(arrived[i]))
	}
	slices.Sort(gaps)
	// The median, which a single long weekend or a burst of reruns does not
	// move.
	usual := gaps[len(gaps)/2]
	if len(gaps)%2 == 0 {
		usual = (gaps[len(gaps)/2-1] + gaps[len(gaps)/2]) / 2
	}
	allowed := max(quietTimes*usual, quietFloor)
	silent := now.Sub(arrived[0])
	return silent, silent > allowed
}

// lastRefused is the last upload of the series to the build turned away after
// its last applied run, or nil where none was.
func (w *sweep) lastRefused(ctx context.Context, build analysisBuild,
	since time.Time) (*series.Refusal, error) {
	var turned []series.Refusal
	err := w.db.NewSelect().Model(&turned).
		Where(`"sx"."build_id" = ?`, build.BuildID).
		Where(`"sx"."kind" = ?`, kind.Analysis).
		Where(`"sx"."series_folded" = ?`, build.Folded).
		Where(`"sx"."at" > ?`, since).
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what was turned away from %s: %w", build.Series, err)
	}
	if len(turned) == 0 {
		return nil, nil
	}
	return &turned[0], nil
}

// rulesOutgrown is every approved suppression rule that covers more
// than its approver saw by the deployment's factor, against whoever may
// approve it again.
//
// It keeps dismissing what it names, so nothing reaches the queue to say the
// agreement no longer matches what it covers. It clears when the rule is
// approved again at its size, retired, or covers less.
func (w *sweep) rulesOutgrown(ctx context.Context) (map[int64][]Holds, error) {
	var products []struct {
		ID    int64  `bun:"id"`
		Name  string `bun:"name"`
		Shown string `bun:"display_name"`
	}
	if err := w.db.NewSelect().
		TableExpr(`"product" AS "p"`).
		ColumnExpr(`"p"."id", "p"."name", "p"."display_name"`).
		Where(`"p"."retired_at" IS NULL`).
		Where(`EXISTS (SELECT 1 FROM "suppression_rule" AS "lr" WHERE "lr"."product_id" = "p"."id" `+
			`AND "lr"."approved_at" IS NOT NULL AND "lr"."retired_at" IS NULL)`).
		Scan(ctx, &products); err != nil {
		return nil, fmt.Errorf("read which products hold suppression rules: %w", err)
	}
	out, err := w.everybody(ctx, SuppressionRuleOutgrown)
	if err != nil {
		return nil, err
	}
	// Counted as the deployment rather than as anybody in it: the count is
	// the rule's size, and who hears it is decided below by who may approve.
	everything := access.Everything("the watch")
	for _, product := range products {
		rules, err := analysis.SuppressionRules(ctx, w.db, everything, product.ID)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			if rule.State != analysis.SuppressionRuleOutgrown || rule.ApprovedCovering == nil {
				continue
			}
			named := rule.Rule
			if rule.Prefix != "" {
				named += " under " + rule.Prefix
			}
			productID := product.ID
			holds := Holds{
				About: identify("suppression-rule-outgrown", strconv.FormatInt(rule.ID, 10)),
				Body: fmt.Sprintf("A suppression rule in %s dismissing %s covers %d code findings, and was approved "+
					"over %d. It keeps dismissing them until somebody approves it again.",
					product.Shown, named, rule.Covering, *rule.ApprovedCovering),
				Link:            weblink.SuppressionRules(product.Name),
				Private:         true,
				SecurityTesting: true,
				ProductID:       &productID,
			}
			for personID, per := range w.reach {
				// Approved again by somebody other than its proposer.
				if personID == rule.ProposedBy || !per[productID].approvesAll(rows{securityTesting: 1}) {
					continue
				}
				out[personID] = append(out[personID], holds)
			}
		}
	}
	return out, nil
}

// rulesWaiting is every suppression rule that nobody has approved, past
// the period a decision may wait on a second person, against whoever may approve
// it.
//
// A proposed rule dismisses nothing, so every code finding it names stays in the
// queue while it waits. It clears when the rule is approved or retired.
func (w *sweep) rulesWaiting(ctx context.Context) (map[int64][]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.WaitingAfter, setting.DefaultWaitingAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long a suppression rule may wait: %w", err)
	}
	since := time.Now().UTC().Add(-after)
	var products []struct {
		ID    int64  `bun:"id"`
		Name  string `bun:"name"`
		Shown string `bun:"display_name"`
	}
	if err := w.db.NewSelect().
		TableExpr(`"product" AS "p"`).
		ColumnExpr(`"p"."id", "p"."name", "p"."display_name"`).
		Where(`"p"."retired_at" IS NULL`).
		Where(`EXISTS (SELECT 1 FROM "suppression_rule" AS "lr" WHERE "lr"."product_id" = "p"."id" `+
			`AND "lr"."approved_at" IS NULL AND "lr"."retired_at" IS NULL AND "lr"."proposed_at" <= ?)`, since).
		Scan(ctx, &products); err != nil {
		return nil, fmt.Errorf("read which products hold suppression rules waiting on a second person: %w", err)
	}
	out, err := w.everybody(ctx, SuppressionRuleWaiting)
	if err != nil {
		return nil, err
	}
	// Read as the deployment, as rulesOutgrown reads them: who hears it is
	// decided below by who may approve.
	everything := access.Everything("the watch")
	for _, product := range products {
		rules, err := analysis.SuppressionRules(ctx, w.db, everything, product.ID)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			if rule.State != analysis.RuleProposed || rule.ProposedAt.After(since) {
				continue
			}
			named := rule.Rule
			switch {
			case named == "":
				named = "every code finding under " + rule.Prefix
			case rule.Prefix != "":
				named += " under " + rule.Prefix
			}
			productID := product.ID
			holds := Holds{
				About: identify("suppression-rule-waiting", strconv.FormatInt(rule.ID, 10)),
				Body: fmt.Sprintf("A suppression rule in %s dismissing %s is waiting for a second person. "+
					"It dismisses nothing until somebody approves it.", product.Shown, named),
				Link:            weblink.SuppressionRules(product.Name),
				Private:         true,
				SecurityTesting: true,
				ProductID:       &productID,
			}
			for personID, per := range w.reach {
				// Approved by somebody other than its proposer.
				if personID == rule.ProposedBy || !per[productID].approvesAll(rows{securityTesting: 1}) {
					continue
				}
				out[personID] = append(out[personID], holds)
			}
		}
	}
	return out, nil
}
