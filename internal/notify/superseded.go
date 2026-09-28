// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// Superseded tells a product's triagers that a merge of two issues met two
// judgments in the product that disagreed, and kept one of them.
//
// Returned as a function for the reason Lapses is: the scanner records what a
// report said, and how anybody hears about it is wired in by the deployment.
func Superseded(db *bun.DB, logger *slog.Logger) func(context.Context, []finding.Displaced) {
	return func(ctx context.Context, gone []finding.Displaced) {
		if len(gone) == 0 {
			return
		}
		if err := tellSuperseded(ctx, db, gone); err != nil && logger != nil {
			logger.Error("could not say that a merge superseded a judgment", "error", err)
		}
	}
}

// supersededAbout is what a telling names about one displaced judgment.
type supersededAbout struct {
	Product  string `bun:"product"`
	IssueID  int64  `bun:"issue_id"`
	Absorbed string `bun:"absorbed"`
	Kept     string `bun:"kept"`
	// Private is whether the telling is held to private triage: a decision's
	// own visibility, or for a judgment about the whole issue in a product,
	// whether no finding of it there is disclosed.
	Private bool `bun:"private"`
}

// supersededSaid is how a telling words each kind of judgment.
var supersededSaid = map[finding.DisplacedKind]string{
	finding.DisplacedDecision: "two decisions in %s disagreed about one place",
	finding.DisplacedRating:   "two ratings of it in %s disagreed",
	finding.DisplacedAttack:   "two records of %s being attacked through it gave different dates",
}

func tellSuperseded(ctx context.Context, db *bun.DB, gone []finding.Displaced) error {
	acts, err := whoActs(ctx, db)
	if err != nil {
		return err
	}
	var failed error
	for _, one := range gone {
		said, known := supersededSaid[one.Kind]
		if !known {
			failed = errors.Join(failed, fmt.Errorf("a merge displaced a judgment of unknown kind %q", one.Kind))
			continue
		}
		q := db.NewSelect().
			TableExpr(`"product" AS "p"`).
			Join(`JOIN "vulnerability_merge" AS "vm" ON vm.id = ?`, one.MergeID).
			Join(`JOIN "vulnerability" AS "va" ON va.id = vm.absorbed_id`).
			Join(`JOIN "vulnerability" AS "vk" ON vk.id = vm.kept_id`).
			ColumnExpr(`p.name AS "product"`).
			ColumnExpr(`vk.issue_id AS "issue_id"`).
			ColumnExpr(`va.identifier AS "absorbed"`).
			ColumnExpr(`vk.identifier AS "kept"`).
			Where("p.id = ?", one.ProductID)
		if one.Kind == finding.DisplacedDecision {
			// Private where either decision is: the one that stands is what
			// the link opens, and the one that lapsed is what the message
			// is about.
			q = q.ColumnExpr(`CASE WHEN EXISTS (SELECT 1 FROM "decision" AS "de" `+
				`WHERE de.id IN (?, ?) AND de.visibility = ?) THEN 1 ELSE 0 END AS "private"`,
				one.RecordID, one.StandingID, string(access.Private))
		} else {
			q = q.ColumnExpr(`CASE WHEN EXISTS (SELECT 1 FROM "finding" AS "f" `+
				`JOIN "target" AS "tg" ON tg.id = f.target_id `+
				`JOIN "stream" AS "st" ON st.id = tg.stream_id `+
				`WHERE f.vulnerability_id = vk.issue_id AND st.product_id = p.id `+
				`AND f.visibility = ?) THEN 0 ELSE 1 END AS "private"`,
				string(access.Public))
		}
		var about supersededAbout
		if err := q.Scan(ctx, &about); err != nil {
			failed = errors.Join(failed, fmt.Errorf("read what a merge superseded: %w", err))
			continue
		}
		link := weblink.Decision(one.StandingID)
		if one.Kind != finding.DisplacedDecision {
			link = weblink.Issue(about.Kept)
		}
		body := fmt.Sprintf("%s merged into %s, and "+said+". The one with more standing "+
			"is kept and the other stopped applying.", about.Absorbed, about.Kept, about.Product)
		for personID, per := range acts {
			if !per[one.ProductID].triages(about.Private) {
				continue
			}
			productID := one.ProductID
			if err := NewStore(db).Tell(ctx, Telling{
				PersonID: personID, Kind: MergeSuperseded,
				Body:            body,
				Link:            link,
				Private:         about.Private,
				ProductID:       &productID,
				VulnerabilityID: &about.IssueID,
			}); err != nil {
				// The merge has committed, so one person not told is no
				// reason to leave the rest untold.
				failed = errors.Join(failed, err)
			}
		}
	}
	return failed
}
