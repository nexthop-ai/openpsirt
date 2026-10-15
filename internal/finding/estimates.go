// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// Writing the newer likelihood estimates a run of reports carries a statement
// per batch of issues rather than one per issue.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// estimated is one newer estimate decided from what was read and waiting to
// be written.
type estimated struct {
	id         int64
	likelihood int
	percentile *int
	on         *time.Time
}

// estimateHeld is estimate for an issue whose row was read with the run: it
// says whether the estimate is newer from the row, and queues the write.
//
// The read answers exactly what the statement's condition would. A dated
// estimate whose day, or the stored day, is not the start of a day in UTC is
// compared the way the engine compares it, which the read cannot reproduce, so
// the issue's own statement is issued and answers.
func (v *Vulnerabilities) estimateHeld(ctx context.Context, row Vulnerability, named Named) (bool, error) {
	if named.Likelihood <= 0 {
		return false, nil
	}
	likelihood := perMillion(named.Likelihood)
	var newer bool
	if on := named.LikelihoodOn; on != nil {
		if row.LikelihoodPPM != nil && row.LikelihoodOn != nil &&
			(!aDay(*on) || !aDay(*row.LikelihoodOn)) {
			return v.estimate(ctx, row.ID, named)
		}
		newer = row.LikelihoodPPM == nil || row.LikelihoodOn == nil || row.LikelihoodOn.Before(*on)
	} else {
		newer = row.LikelihoodPPM == nil || (row.LikelihoodOn == nil && *row.LikelihoodPPM != likelihood)
	}
	if newer {
		v.estimates = append(v.estimates, estimated{
			id: row.ID, likelihood: likelihood,
			percentile: nilWhenZero(perMillion(named.LikelihoodPercentile)),
			on:         named.LikelihoodOn,
		})
	}
	return newer, nil
}

// writeEstimates writes the estimates waiting, a statement per day they are
// about and batch of issues.
//
// The value each issue takes is chosen by a CASE over the issue's identifier,
// which no assignment writes, so the engines that read a value already
// assigned earlier in the list read the same thing as the ones that do not.
// The ELSE names the column, which types the expression on the engine that
// would otherwise read a list of bound values as text; nothing reaches it,
// because the statement names only the issues the CASE does.
//
// The statement keeps the condition the issue's own statement carries, so a
// row another writer has moved since the read is left as that writer left it.
func (v *Vulnerabilities) writeEstimates(ctx context.Context) error {
	if len(v.estimates) == 0 {
		return nil
	}
	pending := v.estimates
	v.estimates = nil
	byDay := map[string][]estimated{}
	for _, each := range pending {
		byDay[instantOf(each.on)] = append(byDay[instantOf(each.on)], each)
	}
	days := make([]string, 0, len(byDay))
	for day := range byDay {
		days = append(days, day)
	}
	sort.Strings(days)
	for _, day := range days {
		group := byDay[day]
		for start := 0; start < len(group); start += database.BatchSize {
			batch := group[start:min(start+database.BatchSize, len(group))]
			ids := make([]int64, len(batch))
			likelihood := make([]any, 0, 2*len(batch))
			percentile := make([]any, 0, 2*len(batch))
			for i, each := range batch {
				ids[i] = each.id
				likelihood = append(likelihood, each.id, each.likelihood)
				percentile = append(percentile, each.id, each.percentile)
			}
			byID := func(column string) string {
				return "CASE id" + strings.Repeat(" WHEN ? THEN ?", len(batch)) + " ELSE " + column + " END"
			}
			on := batch[0].on
			update := v.db.NewUpdate().Model((*Vulnerability)(nil)).
				Set(`"likelihood_ppm" = `+byID("likelihood_ppm"), likelihood...).
				Set(`"likelihood_percentile_ppm" = `+byID("likelihood_percentile_ppm"), percentile...).
				Set(`"likelihood_on" = ?`, on).
				Where(`"id" IN (?)`, bun.List(ids))
			if _, err := newerEstimate(update, on, byID("likelihood_ppm"), likelihood...).Exec(ctx); err != nil {
				return fmt.Errorf("record how likely %d issues are: %w", len(batch), err)
			}
		}
	}
	return nil
}

// newerEstimate is the condition under which a reported estimate replaces the
// one held: the issue's own statement and a batch's carry the same one. The
// likelihood is an expression, so a batch can give each issue its own.
func newerEstimate(update *bun.UpdateQuery, on *time.Time, likelihood string, args ...any) *bun.UpdateQuery {
	if on != nil {
		return update.Where(`"likelihood_ppm" IS NULL OR "likelihood_on" IS NULL OR "likelihood_on" < ?`, *on)
	}
	return update.Where(`"likelihood_ppm" IS NULL OR ("likelihood_on" IS NULL AND "likelihood_ppm" <> `+
		likelihood+")", args...)
}
