// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// heldBy is who a report's holder is: a person, or a team's queue. Neither is
// a report nobody holds.
type heldBy struct {
	person, team int64
}

// partiesOf resolves the parties holding reports to a person or a team, once
// each however many reports one holds.
func partiesOf(ctx context.Context, db bun.IDB, parties []int64) (map[int64]heldBy, error) {
	out := map[int64]heldBy{}
	if len(parties) == 0 {
		return out, nil
	}
	var people []struct {
		ID      int64 `bun:"id"`
		PartyID int64 `bun:"party_id"`
	}
	if err := db.NewSelect().TableExpr(`"person" AS "pe"`).
		ColumnExpr(`"pe"."id" AS "id"`).ColumnExpr(`"pe"."party_id" AS "party_id"`).
		Where(`"pe"."party_id" IN (?)`, bun.List(parties)).Scan(ctx, &people); err != nil {
		return nil, fmt.Errorf("read who holds these reports: %w", err)
	}
	for _, p := range people {
		out[p.PartyID] = heldBy{person: p.ID}
	}
	var teams []struct {
		ID      int64 `bun:"id"`
		PartyID int64 `bun:"party_id"`
	}
	if err := db.NewSelect().TableExpr(`"team" AS "tm"`).
		ColumnExpr(`"tm"."id" AS "id"`).ColumnExpr(`"tm"."party_id" AS "party_id"`).
		Where(`"tm"."party_id" IN (?)`, bun.List(parties)).Scan(ctx, &teams); err != nil {
		return nil, fmt.Errorf("read which teams hold these reports: %w", err)
	}
	for _, t := range teams {
		out[t.PartyID] = heldBy{team: t.ID}
	}
	return out, nil
}

// reportAudience is who hears about one report, in three tiers:
//
//   - the person holding it, where a person does;
//   - the members of the team whose queue it is in, where a team's does;
//   - everybody who works reports in the product, where nobody holds it.
//
// A holder and a team member hear only where they read the product's
// reports, since the line names undisclosed work. A holder nobody here can
// tell is nobody holding it: a person who no longer reads the reports, or a
// queue with no member who does, falls to the third tier, so the report is
// never told to nobody.
type reportAudience struct {
	db      bun.IDB
	reach   map[int64]map[int64]acts
	parties map[int64]heldBy
	members map[int64][]int64
}

// newReportAudience reads who holds each of these parties.
func newReportAudience(ctx context.Context, db bun.IDB, reach map[int64]map[int64]acts,
	held []*int64) (*reportAudience, error) {

	var parties []int64
	for _, h := range held {
		if h != nil {
			parties = append(parties, *h)
		}
	}
	resolved, err := partiesOf(ctx, db, parties)
	if err != nil {
		return nil, err
	}
	return &reportAudience{db: db, reach: reach, parties: resolved, members: map[int64][]int64{}}, nil
}

// of is everybody told about a report in a product held by this party, or by
// nobody.
func (a *reportAudience) of(ctx context.Context, productID int64, held *int64) ([]int64, error) {
	if held == nil {
		var out []int64
		for personID, per := range a.reach {
			if per[productID].triages(true) {
				out = append(out, personID)
			}
		}
		return out, nil
	}
	party, ok := a.parties[*held]
	if !ok {
		return a.of(ctx, productID, nil)
	}
	candidates := []int64{party.person}
	if party.team != 0 {
		members, ok := a.members[party.team]
		if !ok {
			var err error
			members, err = access.NewStore(a.db).MembersOf(ctx, party.team)
			if err != nil {
				return nil, err
			}
			a.members[party.team] = members
		}
		candidates = members
	}
	var out []int64
	for _, personID := range candidates {
		if a.reach[personID][productID].reads(true) {
			out = append(out, personID)
		}
	}
	if len(out) == 0 {
		return a.of(ctx, productID, nil)
	}
	return out, nil
}

// ReportAct is something done on a report that its audience hears of: a
// message from the reporter or to them, or a note.
type ReportAct struct {
	// Kind is ReportMessage for a message received, ReportSent for one sent,
	// and ReportNoted for a note.
	Kind      Kind
	ProductID int64
	// Product is the product's name, as an address names it.
	Product   string
	Reference string
	// AssignedTo is the party holding the report, absent where nobody does.
	AssignedTo *int64
	// By is who did it, and is not told.
	By int64
	// Named is everybody a note named who was told of the mention, and is
	// not told of the note as well.
	Named []int64
}

// reportSaid is the line each act on a report is told in.
var reportSaid = map[Kind]string{
	ReportMessage: "The reporter of %s wrote again, in %s",
	ReportSent:    "A message to the reporter of %s was recorded, in %s",
	ReportNoted:   "A note was written on %s, in %s",
}

// TellReport tells the report's audience what was done on it: the holder,
// the team whose queue it is in, or everybody who works reports in the
// product. The audience is who watches a report. An event, and undisclosed,
// so nothing leaving the deployment names the report.
func TellReport(ctx context.Context, db *bun.DB, act ReportAct) error {
	said, ok := reportSaid[act.Kind]
	if !ok {
		return fmt.Errorf("%s is not something done on a report", act.Kind)
	}
	reach, err := whoActs(ctx, db)
	if err != nil {
		return err
	}
	audience, err := newReportAudience(ctx, db, reach, []*int64{act.AssignedTo})
	if err != nil {
		return err
	}
	told, err := audience.of(ctx, act.ProductID, act.AssignedTo)
	if err != nil {
		return err
	}
	productID := act.ProductID
	var failed error
	for _, personID := range told {
		if personID == act.By || slices.Contains(act.Named, personID) {
			continue
		}
		if err := NewStore(db).Tell(ctx, Telling{
			PersonID: personID, Kind: act.Kind,
			Body:    fmt.Sprintf(said, act.Reference, act.Product),
			Link:    weblink.VulnerabilityReport(act.Product, act.Reference),
			Private: true, ProductID: &productID,
		}); err != nil {
			// Carried on: an event has no retry, so stopping tells a random
			// subset.
			failed = errors.Join(failed, fmt.Errorf("tell %d about a report: %w", personID, err))
		}
	}
	return failed
}
