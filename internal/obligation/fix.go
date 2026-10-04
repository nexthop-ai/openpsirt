// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Fix is a person's statement that a release of the record's product carries
// the fix for the attack.
//
// A tag, and usually one declared before any scan of it: naming the release a
// fix will ship in is the expected case. A window counting from the fix
// counts from the earliest release date stated for one of these.
//
// Withdrawn rather than deleted. A release named in error is corrected by
// withdrawing it, and the naming stays readable with who took it back, the
// way a cleared record does.
type Fix struct {
	bun.BaseModel `bun:"table:exploited_fix,alias:ef"`

	ID              int64      `bun:"id,pk,autoincrement"`
	ExploitedHereID int64      `bun:"exploited_here_id,notnull"`
	StreamID        int64      `bun:"stream_id,notnull"`
	NamedBy         int64      `bun:"named_by,notnull"`
	NamedAt         time.Time  `bun:"named_at,notnull"`
	WithdrawnBy     *int64     `bun:"withdrawn_by"`
	WithdrawnAt     *time.Time `bun:"withdrawn_at"`
	// LiveStreamID is the release while the naming stands, and null once it
	// is withdrawn. Unique beside the record, so a record names a release
	// once at a time, held by the database rather than by a check.
	LiveStreamID *int64 `bun:"live_stream_id"`

	// Release is the name the release's address takes, and ReleaseName its
	// spelling on screen.
	Release     string `bun:"-"`
	ReleaseName string `bun:"-"`
	// ReleasedOn is the release date somebody stated for the release, or nil
	// where nobody has. The day it was declared does not stand in: a release
	// with no stated date has not been said to have gone out.
	ReleasedOn *time.Time `bun:"-"`
	// State is what the release's latest scans say about the issue.
	State finding.ReleaseState `bun:"-"`
}

// Standing says the naming has not been withdrawn.
func (f Fix) Standing() bool { return f.WithdrawnAt == nil }

// ErrFixNamed is returned where the record already names the release.
var ErrFixNamed = refusal.New("this record already names that release as carrying the fix")

// ErrNoSuchFix is returned where a record names no such release, or names it
// no longer.
var ErrNoSuchFix = refusal.New("this record names no such release as carrying the fix")

// ErrNoSuchRelease is returned where the record's product has no release by
// the name given.
var ErrNoSuchRelease = refusal.New("no release of this product goes by that")

// FixAvailable is the moment a window counting from the fix starts: the
// earliest release date stated for a release these namings still name, at
// the start of that day in UTC. False where none of them states one.
func FixAvailable(fixes []Fix) (time.Time, bool) {
	var earliest time.Time
	found := false
	for _, fix := range fixes {
		if !fix.Standing() || fix.ReleasedOn == nil {
			continue
		}
		// The calendar day as stored. A date column read back in a zone
		// other than UTC still carries the stored day in its own fields.
		y, m, d := fix.ReleasedOn.Date()
		on := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
		if !found || on.Before(earliest) {
			earliest, found = on, true
		}
	}
	return earliest, found
}

// NameFix records that a release of the record's product carries the fix.
//
// Asked of triage on the record's product, which is what recording the attack
// asks. A tag rather than a branch, because a branch moves and a fix is in one
// frozen point; and not a retired one, which is out of use. Only on a record
// that stands: a cleared record is read as it stood when it was cleared.
func (s *Store) NameFix(ctx context.Context, subject access.Subject, recordID int64,
	release string) (*Fix, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, refusal.New("a release carrying the fix is named against whoever named it")
	}
	release = strings.TrimSpace(release)
	if release == "" {
		return nil, refusal.New("say which release carries the fix")
	}
	fix := new(Fix)
	err := s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		*fix = Fix{}
		record, err := standingFor(ctx, tx, subject, recordID)
		if err != nil {
			return err
		}
		stream := new(catalog.Stream)
		if err := tx.NewSelect().Model(stream).
			Where("s.product_id = ?", record.ProductID).
			Where("s.name = ?", catalog.Matching(release)).
			Scan(ctx); err != nil {
			if database.IsNoRows(err) {
				return ErrNoSuchRelease
			}
			return fmt.Errorf("read the release carrying the fix: %w", err)
		}
		if stream.Kind != catalog.Tag {
			return refusal.Errorf("%q is a branch, which moves. A fix is named in a tag", stream.Name)
		}
		if stream.Retired() {
			return refusal.Errorf("%q is retired", stream.Name)
		}
		*fix = Fix{
			ExploitedHereID: record.ID, StreamID: stream.ID,
			NamedBy: subject.ID, NamedAt: s.now().Truncate(time.Microsecond),
			LiveStreamID: &stream.ID,
			Release:      stream.Name, ReleaseName: catalog.Shown(stream.DisplayName, stream.Name),
			ReleasedOn: stream.ReleasedOn,
		}
		if _, err := tx.NewInsert().Model(fix).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				return ErrFixNamed
			}
			return fmt.Errorf("name the release carrying the fix: %w", err)
		}
		return noteFix(ctx, tx, subject, record, nil, trail.Said(stream.Name, true))
	})
	if err != nil {
		return nil, err
	}
	return fix, nil
}

// WithdrawFix takes back a release named on the record as carrying the fix.
//
// The naming stays readable with who withdrew it and when. A window counting
// from the fix moves to the earliest release date the record still names, or
// stops counting where none states one.
func (s *Store) WithdrawFix(ctx context.Context, subject access.Subject, recordID,
	fixID int64) error {

	if subject.Kind != access.Person || subject.ID == 0 {
		return refusal.New("withdrawing a release carrying the fix is recorded against whoever did it")
	}
	return s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		record, err := standingFor(ctx, tx, subject, recordID)
		if err != nil {
			return err
		}
		fix := new(Fix)
		if err := tx.NewSelect().Model(fix).
			Where("ef.id = ?", fixID).Where("ef.exploited_here_id = ?", record.ID).
			Where("ef.withdrawn_at IS NULL").
			Scan(ctx); err != nil {
			if database.IsNoRows(err) {
				return ErrNoSuchFix
			}
			return fmt.Errorf("read the release named as carrying the fix: %w", err)
		}
		res, err := tx.NewUpdate().Model((*Fix)(nil)).
			Set("withdrawn_at = ?", s.now().Truncate(time.Microsecond)).
			Set("withdrawn_by = ?", subject.ID).
			// Released, so the release may be named again.
			Set("live_stream_id = ?", nil).
			Where("id = ?", fix.ID).
			// Still standing when this lands. Two people withdrawing at once
			// would otherwise both write, and the trail would say it twice.
			Where("withdrawn_at IS NULL").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("withdraw the release named as carrying the fix: %w", err)
		}
		changed, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("withdraw the release named as carrying the fix: %w", err)
		}
		if changed == 0 {
			return ErrNoSuchFix
		}
		var name string
		if err := tx.NewSelect().Model((*catalog.Stream)(nil)).ColumnExpr("s.name").
			Where("s.id = ?", fix.StreamID).Scan(ctx, &name); err != nil {
			return fmt.Errorf("read the release named as carrying the fix: %w", err)
		}
		return noteFix(ctx, tx, subject, record, trail.Said(name, true), nil)
	})
}

// standingFor reads a record this subject may act on, inside the write that
// acts on it, and refuses one that is cleared.
//
// The record is written first, unchanged, while it stands, before anything
// is read. Clearing writes the same row, so a clearing and a naming wait for
// each other, and the one that goes second reads what the first committed: a
// naming never lands on a record cleared after it was read
// (`DESIGN-database.md` § Reads a write depends on). The write changes
// nothing, so it says nothing to a subject the reads below then refuse.
func standingFor(ctx context.Context, tx bun.IDB, subject access.Subject,
	recordID int64) (*triage.ExploitedHere, error) {

	if _, err := tx.NewUpdate().Model((*triage.ExploitedHere)(nil)).
		Set("cleared_at = cleared_at").
		Where("id = ?", recordID).Where("cleared_at IS NULL").
		Exec(ctx); err != nil {
		return nil, fmt.Errorf("hold the record of being exploited: %w", err)
	}
	record := new(triage.ExploitedHere)
	if err := tx.NewSelect().Model(record).Where("eh.id = ?", recordID).
		Scan(ctx); err != nil {
		if database.IsNoRows(err) {
			return nil, ErrNoSuchRecord
		}
		return nil, fmt.Errorf("read the record of being exploited: %w", err)
	}
	if !subject.TriagesIn(record.ProductID) {
		return nil, ErrNoSuchRecord
	}
	allowed, err := finding.MayBeToldOfWithin(ctx, tx, subject,
		record.ProductID, record.VulnerabilityID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrNoSuchRecord
	}
	if !record.Standing() {
		return nil, refusal.New("this record is cleared, and a cleared record is read as it " +
			"stood. Name the release on the record that stands")
	}
	return record, nil
}

// noteFix writes a release named or withdrawn into the administrative trail,
// in the transaction that makes it, beside the record it belongs to.
func noteFix(ctx context.Context, tx bun.IDB, subject access.Subject,
	record *triage.ExploitedHere, was, became *string) error {

	var named struct {
		Issue   string `bun:"issue"`
		Product string `bun:"product"`
	}
	err := tx.NewSelect().
		TableExpr(`"vulnerability" AS "v"`).
		ColumnExpr(`v.identifier AS "issue"`).
		ColumnExpr(`(SELECT p.name FROM "product" AS "p" WHERE p.id = ?) AS "product"`,
			record.ProductID).
		Where("v.id = ?", record.VulnerabilityID).
		Scan(ctx, &named)
	if err != nil {
		return fmt.Errorf("read what this record is about: %w", err)
	}
	return trail.NewStore(tx).Record(ctx, subject, trail.ExploitedHere,
		named.Issue+" on "+named.Product+", fix release", was, became)
}

// FixesOf is every release named on these records as carrying the fix that
// this subject may be told of, withdrawn ones among them, earliest named
// first, each with its release date and what its latest scans say.
//
// Narrowed by the record each naming is about, with the question that
// authorizes one issue in one product, as the notices are.
func (s *Store) FixesOf(ctx context.Context, subject access.Subject,
	recordIDs []int64) (map[int64][]Fix, error) {

	out := map[int64][]Fix{}
	if len(recordIDs) == 0 {
		return out, nil
	}
	var records []triage.ExploitedHere
	if err := s.db.NewSelect().Model(&records).
		Where("eh.id IN (?)", bun.List(recordIDs)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the records of being exploited: %w", err)
	}
	allowed := make(map[int64]triage.ExploitedHere, len(records))
	ids := make([]int64, 0, len(records))
	for _, record := range records {
		ok, err := finding.MayBeToldOfWithin(ctx, s.db, subject,
			record.ProductID, record.VulnerabilityID)
		if err != nil {
			return nil, err
		}
		if ok {
			allowed[record.ID] = record
			ids = append(ids, record.ID)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		Fix `bun:"extend"`

		Name        string     `bun:"release"`
		DisplayName string     `bun:"release_display"`
		On          *time.Time `bun:"released_on"`
	}
	if err := s.db.NewSelect().
		Model((*Fix)(nil)).
		ColumnExpr("ef.*").
		ColumnExpr(`st.name AS "release"`).
		ColumnExpr(`st.display_name AS "release_display"`).
		ColumnExpr(`st.released_on AS "released_on"`).
		Join(`JOIN "stream" AS "st" ON st.id = ef.stream_id`).
		Where("ef.exploited_here_id IN (?)", bun.List(ids)).
		Order("ef.named_at ASC", "ef.id ASC").
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the releases named as carrying the fix: %w", err)
	}
	for _, row := range rows {
		fix := row.Fix
		fix.Release, fix.ReleaseName = row.Name, catalog.Shown(row.DisplayName, row.Name)
		fix.ReleasedOn = row.On
		out[fix.ExploitedHereID] = append(out[fix.ExploitedHereID], fix)
	}
	for recordID, fixes := range out {
		record := allowed[recordID]
		streams := make([]int64, 0, len(fixes))
		for _, fix := range fixes {
			streams = append(streams, fix.StreamID)
		}
		states, err := finding.HeldOpenIn(ctx, s.db, subject, record.ProductID,
			record.VulnerabilityID, streams)
		if err != nil {
			return nil, err
		}
		for i := range fixes {
			fixes[i].State = states[fixes[i].StreamID]
		}
	}
	return out, nil
}
