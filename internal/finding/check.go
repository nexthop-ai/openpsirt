// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Replaced is one branch inventory a later one replaced, and what checking it
// works from.
type Replaced struct {
	BuildID int64
	// ScanID is the replaced inventory and ReplacementID the one after it.
	ScanID, ReplacementID int64
	// ArrivedAt is when the replaced inventory arrived and ReplacedAt when
	// its replacement did.
	ArrivedAt, ReplacedAt time.Time
	// Since is the date of the vulnerability data the replaced inventory was
	// last scanned with, absent where no scan reached it.
	Since *time.Time
	// Lag is how long an issue may take to reach the scanner's data after it
	// is published: the window opens that long before Since, since data dated
	// Since need not yet carry an issue published just before it.
	Lag time.Duration
}

// DataDate is when the vulnerability data a run matched against was built,
// or when the run started where the scanner names its data some other way.
func DataDate(databaseVersion string, started time.Time) time.Time {
	if built, err := time.Parse(time.RFC3339Nano, databaseVersion); err == nil {
		return built.UTC()
	}
	return started.UTC()
}

// LastScanned is the data date of the scan that last reached an inventory of
// a build current from arrived until replaced: a successful run of the build,
// other than a check, that started while it was current. Absent where no scan
// reached it.
func LastScanned(ctx context.Context, db bun.IDB, buildID int64, arrived, replaced time.Time) (*time.Time, error) {
	var last []Run
	if err := db.NewSelect().Model(&last).
		Column("database_version", "started_at").
		Where(`"build_id" = ?`, buildID).
		Where(`"checked_scan_id" IS NULL`).
		Where(`"finished_at" IS NOT NULL`).
		Where(`COALESCE("failure", '') = ''`).
		Where(`"started_at" >= ?`, arrived).
		Where(`"started_at" < ?`, replaced).
		Order("started_at DESC", "id DESC").Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read when the replaced inventory was last scanned: %w", err)
	}
	if len(last) == 0 {
		return nil, nil
	}
	dated := DataDate(last[0].DatabaseVersion, last[0].StartedAt)
	return &dated, nil
}

// Checked is what checking a replaced inventory recorded.
type Checked struct {
	// Dated is how many reports fell between the last scan of the replaced
	// inventory and its replacement, and Recorded how many findings that
	// placed, closed, where nothing already said so.
	Dated, Recorded int
}

// datesSettle is how long a check waits for OSV to be asked about an issue
// before dating it by its first sighting.
const datesSettle = 24 * time.Hour

// Undated files the issues a check reports that nothing here holds, so the
// date pass can ask about them, and counts those still waiting on it: every
// issue not yet asked about, for a day after the later of its first sighting
// and owed, when the check fell due. Bounded from the check falling due, so a
// backlog the pass has not reached waits rather than spending the one check;
// bounded at all, so an OSV outage cannot hold every check.
//
// Only while the dates are asked: with the pass off, an issue first seen by
// the check is dated by that sighting, which falls after the replacement.
func (s *Store) Undated(ctx context.Context, reported []Reported, asking bool, owed time.Time) (int, error) {
	if !asking || len(reported) == 0 {
		return 0, nil
	}
	waiting := 0
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		waiting = 0
		known, err := knownIssues(ctx, tx, reported)
		if err != nil {
			return err
		}
		var unknown []Named
		for _, r := range reported {
			if _, held := known[normalize(r.Issue.Identifier)]; !held {
				unknown = append(unknown, r.Issue)
			}
		}
		if len(unknown) > 0 {
			if _, err := NewVulnerabilities(tx).Intern(ctx, unknown); err != nil {
				return err
			}
			if known, err = knownIssues(ctx, tx, reported); err != nil {
				return err
			}
		}
		recent := s.now().Add(-datesSettle)
		for _, d := range known {
			from := d.firstSeen
			if owed.After(from) {
				from = owed
			}
			if d.asked == nil && from.After(recent) {
				waiting++
			}
		}
		return nil
	})
	return waiting, err
}

// issueDating is what dates one issue for a check.
type issueDating struct {
	published *time.Time
	asked     *time.Time
	firstSeen time.Time
}

// at is when the issue became known: when OSV says it was published, or when
// this deployment first carried it where OSV gives no date.
func (d issueDating) at() time.Time {
	if d.published != nil {
		return *d.published
	}
	return d.firstSeen
}

// unknown says OSV was asked and gave no date, and nothing here carried the
// issue before the replacement, so neither dates it while the inventory was
// current. An issue nobody asked about is dated by its sighting instead: with
// the date pass off, every issue new to this deployment would read as one.
func (d issueDating) unknown(replacedAt time.Time) bool {
	return d.published == nil && d.asked != nil && !d.firstSeen.Before(replacedAt)
}

// knownIssues dates every reported issue this deployment holds, by the
// normalized identifier each report names it by and by the issue it stands as.
func knownIssues(ctx context.Context, db bun.IDB, reported []Reported) (map[string]issueDating, error) {
	byReport := map[string]int64{}
	var names []string
	seen := map[string]bool{}
	for _, r := range reported {
		for _, name := range append([]string{r.Issue.Identifier}, r.Issue.Aliases...) {
			if n := normalize(name); n != "" && !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	var aliases []Alias
	for from := 0; from < len(names); from += database.BatchSize {
		var batch []Alias
		if err := db.NewSelect().Model(&batch).
			Column("identifier", "vulnerability_id").
			Where(`"identifier" IN (?)`, bun.List(names[from:min(from+database.BatchSize, len(names))])).
			Scan(ctx); err != nil {
			return nil, fmt.Errorf("read which issues a check reported: %w", err)
		}
		aliases = append(aliases, batch...)
	}
	rowOf := make(map[string]int64, len(aliases))
	rows := make([]int64, 0, len(aliases))
	for _, a := range aliases {
		rowOf[a.Identifier] = a.VulnerabilityID
		rows = append(rows, a.VulnerabilityID)
	}
	for _, r := range reported {
		for _, name := range append([]string{r.Issue.Identifier}, r.Issue.Aliases...) {
			if id, ok := rowOf[normalize(name)]; ok {
				byReport[normalize(r.Issue.Identifier)] = id
				break
			}
		}
	}
	dated := map[int64]issueDating{}
	err := database.IDsInBatches(ctx, rows, func(ctx context.Context, batch []int64) error {
		var found []struct {
			ID          int64      `bun:"id"`
			PublishedAt *time.Time `bun:"published_at"`
			AskedAt     *time.Time `bun:"dates_asked_at"`
			FirstSeenAt time.Time  `bun:"first_seen_at"`
		}
		if err := db.NewSelect().
			TableExpr(`"vulnerability" AS "v"`).
			Join(`JOIN "vulnerability" AS "s" ON "s"."id" = "v"."issue_id"`).
			ColumnExpr(`"v"."id" AS "id"`).
			ColumnExpr(`"s"."published_at" AS "published_at"`).
			ColumnExpr(`"s"."dates_asked_at" AS "dates_asked_at"`).
			ColumnExpr(`"s"."first_seen_at" AS "first_seen_at"`).
			Where(`"v"."id" IN (?)`, bun.List(batch)).
			Scan(ctx, &found); err != nil {
			return err
		}
		for _, f := range found {
			dated[f.ID] = issueDating{published: f.PublishedAt,
				asked: f.AskedAt, firstSeen: f.FirstSeenAt}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read when the issues a check reported were published: %w", err)
	}
	out := make(map[string]issueDating, len(byReport))
	for name, id := range byReport {
		if d, ok := dated[id]; ok {
			out[name] = d
		}
	}
	return out, nil
}

// CheckReplaced records what a replaced inventory held that no scan saw: the
// issues published between its last scan and its replacement that match it
// and not the inventory after it.
//
// Each is written closed, opening at the later of its publication and the
// inventory's arrival and closing at the replacement, for the reason the
// replacement gives. An issue with no date opens at its first sighting here,
// except one OSV was asked about and first seen at or after the replacement:
// that opens at the later of the last scan's data date and the arrival, until
// Redate corrects it. Nothing is told of it and nothing is assigned: it was
// fixed before anybody could act. A run stays the authority on what it
// reported, so an occurrence any row already covers over that stretch is left
// alone.
func (s *Store) CheckReplaced(ctx context.Context, r Replaced, runID int64, reported []Reported) (Checked, error) {
	var checked Checked
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		checked = Checked{}
		// Taken first, as applying a scan takes it, so a scan of the build
		// and a check of it do not interleave.
		if _, err := tx.NewUpdate().Table("build").
			Set(`"last_run_id" = "last_run_id"`).
			Where(`"id" = ?`, r.BuildID).Exec(ctx); err != nil {
			return fmt.Errorf("take the build: %w", err)
		}
		known, err := knownIssues(ctx, tx, reported)
		if err != nil {
			return err
		}
		var kept []Reported
		published := map[string]time.Time{}
		for _, one := range reported {
			d, ok := known[normalize(one.Issue.Identifier)]
			if !ok {
				continue
			}
			when := d.at()
			if d.unknown(r.ReplacedAt) {
				// The widest stretch it could have been held over; the date
				// pass corrects it once OSV dates the issue.
				when = r.ArrivedAt
				if r.Since != nil && r.Since.After(when) {
					when = *r.Since
				}
			}
			if (r.Since != nil && when.Before(r.Since.Add(-r.Lag))) || !when.Before(r.ReplacedAt) {
				continue
			}
			kept = append(kept, one)
			published[normalize(one.Issue.Identifier)] = when
		}
		checked.Dated = len(kept)
		if len(kept) == 0 {
			return nil
		}

		before, err := s.readRun(ctx, tx, r.BuildID, runID, kept, graph.AtScan(r.ScanID))
		if err != nil {
			return err
		}
		after, err := s.readRun(ctx, tx, r.BuildID, runID, kept, graph.AtScan(r.ReplacementID))
		if err != nil {
			return err
		}
		publishedOf := map[int64]time.Time{}
		for name, when := range published {
			if id, ok := before.vulnerabilities[name]; ok {
				publishedOf[id] = when
			}
		}
		wantBefore, err := before.wanted(kept)
		if err != nil {
			return err
		}
		wantAfter, err := after.wanted(kept)
		if err != nil {
			return err
		}
		// Where the replacement stands at each occurrence identity.
		// The claim a patch stands on and the statement a disclaimer does are
		// carried onto the row, as a run records them, so what reads the
		// latest row at an occurrence still finds them.
		type standing struct {
			open, patched, disclaimed bool
			cleared                   string
			suppressedBy, claimedBy   *int64
			statedBy                  int64
		}
		afterAt := map[at]standing{}
		for k, f := range wantAfter.findings {
			was := afterAt[at{k.vulnerabilityID, f.OccurrenceIdentity}]
			switch {
			case wantAfter.patched[k]:
				was.patched = true
				was.suppressedBy, was.claimedBy = f.SuppressedBy, f.ClaimedBy
			case wantAfter.cleared[k] != "":
				was.cleared = wantAfter.cleared[k]
			case wantAfter.disclaimed[k] != 0:
				was.disclaimed = true
				was.statedBy = wantAfter.disclaimed[k]
			default:
				was.open = true
			}
			afterAt[at{k.vulnerabilityID, f.OccurrenceIdentity}] = was
		}

		var writing []Finding
		var issues []int64
		for k, f := range wantBefore.findings {
			if wantBefore.patched[k] || wantBefore.cleared[k] != "" || wantBefore.disclaimed[k] != 0 {
				continue
			}
			then := afterAt[at{k.vulnerabilityID, f.OccurrenceIdentity}]
			if then.open {
				// The replacement is affected too: its own scan reports it.
				continue
			}
			var reason Closure
			switch {
			case then.patched:
				reason, f.SuppressedBy, f.ClaimedBy = Patched, then.suppressedBy, then.claimedBy
			case then.cleared != "":
				reason, f.UnaffectedBy = Unaffected, then.cleared
			case then.disclaimed:
				reason, f.StatedBy = Disclaimed, &then.statedBy
			default:
				reason, f.MovedTo = after.present.why(before.present.byID[k.occurrence.componentID])
			}
			opened := publishedOf[k.vulnerabilityID]
			if opened.Before(r.ArrivedAt) {
				opened = r.ArrivedAt
			}
			closed := r.ReplacedAt
			f.OpenedAt = opened.UTC().Truncate(time.Microsecond)
			f.ClosedAt = &closed
			f.ClosedBecause = reason
			f.ClosedRunID = &runID
			f.DueAt = nil
			writing = append(writing, f)
			issues = append(issues, k.vulnerabilityID)
		}
		if len(writing) == 0 {
			return Reranked(ctx, tx, before.interned.Moved(), before.startedAt, r.BuildID)
		}
		covered, err := coveredOver(ctx, tx, r.BuildID, issues)
		if err != nil {
			return err
		}
		fresh := writing[:0]
		for _, f := range writing {
			if !covered.over(at{f.VulnerabilityID, f.OccurrenceIdentity}, f.OpenedAt, *f.ClosedAt) {
				fresh = append(fresh, f)
			}
		}
		if len(fresh) == 0 {
			return Reranked(ctx, tx, before.interned.Moved(), before.startedAt, r.BuildID)
		}
		if err := database.InBatches(ctx, tx, fresh); err != nil {
			return fmt.Errorf("record %d findings fixed before any scan saw them: %w", len(fresh), err)
		}
		checked.Recorded = len(fresh)
		return Reranked(ctx, tx, before.interned.Moved(), before.startedAt, r.BuildID)
	})
	return checked, err
}

// stretches is every stretch a build's rows held each occurrence identity
// open over.
type stretches map[at][][2]*time.Time

// over says a row already held this occurrence over part of this stretch.
func (s stretches) over(where at, from, until time.Time) bool {
	for _, held := range s[where] {
		if held[0].Before(until) && (held[1] == nil || held[1].After(from)) {
			return true
		}
	}
	return false
}

// coveredOver reads the stretch of every row of these issues in the build.
func coveredOver(ctx context.Context, db bun.IDB, buildID int64, issues []int64) (stretches, error) {
	out := stretches{}
	err := database.IDsInBatches(ctx, issues, func(ctx context.Context, batch []int64) error {
		var rows []struct {
			VulnerabilityID    int64      `bun:"vulnerability_id"`
			OccurrenceIdentity string     `bun:"occurrence_identity"`
			OpenedAt           time.Time  `bun:"opened_at"`
			ClosedAt           *time.Time `bun:"closed_at"`
		}
		if err := db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			ColumnExpr(`"f"."vulnerability_id", "f"."occurrence_identity", "f"."opened_at", "f"."closed_at"`).
			Where(`"f"."build_id" = ?`, buildID).
			Where(`"f"."vulnerability_id" IN (?)`, bun.List(batch)).
			Scan(ctx, &rows); err != nil {
			return err
		}
		for _, row := range rows {
			opened := row.OpenedAt
			where := at{row.VulnerabilityID, row.OccurrenceIdentity}
			out[where] = append(out[where], [2]*time.Time{&opened, row.ClosedAt})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read what a build already records of these issues: %w", err)
	}
	return out, nil
}
