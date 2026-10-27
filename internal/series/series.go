// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package series holds results a producer sends per series: one analysis
// a product runs the same way on every build, each run of it against a
// build, and what each run saw and did not see.
//
// Built for any kind whose producer sends results that way. Static analysis
// is the first.
package series

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

// Status is what became of a run.
type Status string

const (
	// Queued is a run stored and not yet read.
	Queued Status = "queued"
	// Waiting is a run whose build has no inventory read yet. It is read
	// once one is.
	Waiting Status = "waiting"
	// Applied is a run read and applied.
	Applied Status = "applied"
	// Superseded is a run older than one already applied to its build. It is
	// kept and changes nothing.
	Superseded Status = "superseded"
	// Failed is a run that could not be read, or whose tool did not run.
	Failed Status = "failed"
)

// Statuses is every status a run may hold.
func Statuses() []Status { return []Status{Queued, Waiting, Applied, Superseded, Failed} }

// Series is one analysis a product runs the same way on every build.
type Series struct {
	bun.BaseModel `bun:"table:series,alias:se"`

	ID         int64     `bun:"id,pk,autoincrement"`
	ProductID  int64     `bun:"product_id,notnull"`
	Kind       kind.Kind `bun:"kind,notnull"`
	Name       string    `bun:"name,notnull"`
	NameFolded string    `bun:"name_folded,notnull"`
	CreatedAt  time.Time `bun:"created_at,notnull"`
}

// Run is one run of a series against one build.
type Run struct {
	bun.BaseModel `bun:"table:series_run,alias:sr"`

	ID           int64     `bun:"id,pk,autoincrement"`
	SeriesID     int64     `bun:"series_id,notnull"`
	BuildID      int64     `bun:"build_id,notnull"`
	ContentHash  string    `bun:"content_hash,notnull"`
	SourceCommit string    `bun:"source_commit,nullzero"`
	BuiltAt      time.Time `bun:"built_at,notnull"`
	ReceivedAt   time.Time `bun:"received_at,notnull"`
	Credential   string    `bun:"credential,nullzero"`
	Status       Status    `bun:"status,notnull"`
	Failure      string    `bun:"failure,nullzero"`
	Params                 // what the run says about itself
	Comparable   *bool     `bun:"comparable"`
	Reason       Reason    `bun:"not_comparable,nullzero"`
	ScanID       *int64    `bun:"scan_id"`
	// Fingerprints is the schemes the run's results carry and the mark of
	// the salt the client's is taken with, empty where it reported nothing.
	// A change from the build's last is a fingerprint change.
	Fingerprints        string     `bun:"fingerprints,nullzero"`
	FingerprintsChanged bool       `bun:"fingerprints_changed,notnull"`
	Receipt             string     `bun:"receipt,nullzero"`
	AppliedAt           *time.Time `bun:"applied_at"`
}

// Params is what a run says about itself: in its documents, or beside them in
// the request where the documents say nothing.
type Params struct {
	ToolName      string `bun:"tool_name,nullzero"`
	ToolVersion   string `bun:"tool_version,nullzero"`
	ClientVersion string `bun:"client_version,nullzero"`
	// RulesDigest and RulesCount are the rules enabled: a digest of their
	// identifiers, sorted, and how many.
	RulesDigest   string `bun:"rules_digest,nullzero"`
	RulesCount    *int   `bun:"rules_count"`
	UnitsExpected *int   `bun:"units_expected"`
	UnitsAnalyzed *int   `bun:"units_analyzed"`
	ExitStatus    *int   `bun:"exit_status"`
	// Completed is what the tool said of its own run.
	Completed *bool `bun:"completed"`
	// ThirdParty is the paths the pipeline names as code it did not write,
	// as a JSON list.
	ThirdParty string `bun:"third_party,nullzero"`
}

// Module is one repository a run's checkout held.
type Module struct {
	bun.BaseModel `bun:"table:series_module,alias:sm"`

	ID       int64  `bun:"id,pk,autoincrement"`
	RunID    int64  `bun:"run_id,notnull"`
	Path     string `bun:"path,notnull"`
	Remote   string `bun:"remote,nullzero"`
	Revision string `bun:"revision,nullzero"`
	Changed  bool   `bun:"changed,notnull"`
}

// Store reads and writes series and their runs.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

// NewStore returns a store over db, which may be a transaction.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Arriving is a run as it arrives.
type Arriving struct {
	ProductID   int64
	BuildID     int64
	Kind        kind.Kind
	Series      string
	ContentHash string
	Commit      string
	BuiltAt     time.Time
	Credential  string
	Params      Params
}

// ErrUnnamed refuses a run that names no series.
var ErrUnnamed = refusal.New("the run names no series: send one, or write it into the run's automation identifier")

// ErrBuiltInFuture refuses a run stating a build time ahead of this
// deployment's clock. Runs are ordered by it, so one dated ahead would leave
// every run after it superseded.
var ErrBuiltInFuture = refusal.New("the run states a build time in the future; check the build host's clock")

// futureTolerance is how far ahead of this deployment's clock a build time
// may be, for clocks that disagree by a little.
const futureTolerance = 5 * time.Minute

// Receive records an arriving run, or answers the run it repeats. A repeat
// is the same documents for the same series and build; it is reported, and
// nothing is written.
func (s *Store) Receive(ctx context.Context, a Arriving) (*Run, bool, error) {
	if !kind.Known(a.Kind) {
		return nil, false, fmt.Errorf("receive a run: %q is not a kind of finding", a.Kind)
	}
	typed := strings.TrimSpace(a.Series)
	if typed == "" {
		return nil, false, ErrUnnamed
	}
	if n := utf8.RuneCountInString(typed); n > database.NameWidth {
		return nil, false, refusal.Errorf("the series name is %d characters, and one may be at most %d", n, database.NameWidth)
	}
	if a.BuiltAt.After(s.now().Add(futureTolerance)) {
		return nil, false, ErrBuiltInFuture
	}
	series, err := s.series(ctx, a.ProductID, a.Kind, typed)
	if err != nil {
		return nil, false, err
	}
	var held Run
	err = s.db.NewSelect().Model(&held).
		Where(`"sr"."series_id" = ?`, series.ID).
		Where(`"sr"."build_id" = ?`, a.BuildID).
		Where(`"sr"."content_hash" = ?`, a.ContentHash).
		Scan(ctx)
	switch {
	case err == nil:
		return &held, true, nil
	case !errors.Is(err, sql.ErrNoRows):
		return nil, false, fmt.Errorf("look for the run this repeats: %w", err)
	}
	now := s.now().Truncate(time.Microsecond)
	run := &Run{
		SeriesID: series.ID, BuildID: a.BuildID, ContentHash: a.ContentHash,
		SourceCommit: a.Commit, BuiltAt: a.BuiltAt.UTC().Truncate(time.Microsecond),
		ReceivedAt: now, Credential: a.Credential, Status: Queued, Params: a.Params,
	}
	if _, err := s.db.NewInsert().Model(run).Exec(ctx); err != nil {
		if database.IsDuplicate(err) {
			// The same documents arriving twice at once. The retry finds the
			// one that landed and answers it as a repeat.
			return nil, false, fmt.Errorf("record the run: %w", database.ErrGoAgain)
		}
		return nil, false, fmt.Errorf("record the run: %w", err)
	}
	return run, false, nil
}

// series is the product's series of this kind under this name, made where
// there is none.
func (s *Store) series(ctx context.Context, productID int64, k kind.Kind, typed string) (*Series, error) {
	var found Series
	err := s.db.NewSelect().Model(&found).
		Where(`"se"."product_id" = ?`, productID).
		Where(`"se"."kind" = ?`, k).
		Where(`"se"."name_folded" = ?`, typedname.Matching(typed)).
		Scan(ctx)
	if err == nil {
		return &found, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("look up the series: %w", err)
	}
	made := &Series{
		ProductID: productID, Kind: k, Name: typed, NameFolded: typedname.Matching(typed),
		CreatedAt: s.now().Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(made).Exec(ctx); err != nil {
		if database.IsDuplicate(err) {
			return nil, fmt.Errorf("record the series: %w", database.ErrGoAgain)
		}
		return nil, fmt.Errorf("record the series: %w", err)
	}
	return made, nil
}

// ByID is one run.
func (s *Store) ByID(ctx context.Context, id int64) (*Run, error) {
	var run Run
	if err := s.db.NewSelect().Model(&run).Where(`"sr"."id" = ?`, id).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read run %d: %w", id, err)
	}
	return &run, nil
}

// SeriesOf is the series a run belongs to.
func (s *Store) SeriesOf(ctx context.Context, run *Run) (*Series, error) {
	var found Series
	if err := s.db.NewSelect().Model(&found).Where(`"se"."id" = ?`, run.SeriesID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read series %d: %w", run.SeriesID, err)
	}
	return &found, nil
}

// Previous is the newest run of the same series applied to the same build,
// and nil where there is none.
func (s *Store) Previous(ctx context.Context, run *Run) (*Run, error) {
	var prev Run
	err := s.db.NewSelect().Model(&prev).
		Where(`"sr"."series_id" = ?`, run.SeriesID).
		Where(`"sr"."build_id" = ?`, run.BuildID).
		Where(`"sr"."status" = ?`, Applied).
		Where(`"sr"."id" <> ?`, run.ID).
		OrderExpr(`"sr"."built_at" DESC, "sr"."id" DESC`).
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the run before this one: %w", err)
	}
	return &prev, nil
}

// LastPrinted is the fingerprints of the newest run applied to this run's
// build that reported anything, or empty where none has.
func (s *Store) LastPrinted(ctx context.Context, run *Run) (string, error) {
	return s.LastPrintedOn(ctx, run, run.BuildID)
}

// LastPrintedOn is the fingerprints of the newest run of this run's series
// applied to a build that reported anything, other than this run, or empty
// where none has.
func (s *Store) LastPrintedOn(ctx context.Context, run *Run, buildID int64) (string, error) {
	var prints []string
	err := s.db.NewSelect().Model((*Run)(nil)).Column("fingerprints").
		Where(`"sr"."series_id" = ?`, run.SeriesID).
		Where(`"sr"."build_id" = ?`, buildID).
		Where(`"sr"."status" = ?`, Applied).
		Where(`"sr"."fingerprints" IS NOT NULL`).
		Where(`"sr"."id" <> ?`, run.ID).
		OrderExpr(`"sr"."built_at" DESC, "sr"."id" DESC`).
		Limit(1).
		Scan(ctx, &prints)
	if err != nil {
		return "", fmt.Errorf("read the fingerprints the build last carried: %w", err)
	}
	if len(prints) == 0 {
		return "", nil
	}
	return prints[0], nil
}

// Mark records what became of a run. The status, the failure, whether it is
// comparable and why not, the inventory it was read against, the
// fingerprints and whether they changed, the receipt and when it was applied are written; everything
// else on the run is as it arrived.
func (s *Store) Mark(ctx context.Context, run *Run) error {
	if run.Status == Applied && run.AppliedAt == nil {
		at := s.now().Truncate(time.Microsecond)
		run.AppliedAt = &at
	}
	_, err := s.db.NewUpdate().Model(run).
		Column("status", "failure", "comparable", "not_comparable", "scan_id", "fingerprints",
			"fingerprints_changed", "receipt",
			"applied_at", "tool_name", "tool_version", "client_version", "rules_digest", "rules_count",
			"units_expected", "units_analyzed", "exit_status", "completed").
		WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("record what became of run %d: %w", run.ID, err)
	}
	return nil
}

// Take holds a run's series until the transaction ends, so two runs of one
// series are applied one after the other. Each reads what the series last
// saw, and two at once would both read it before either wrote: one result
// opened twice.
//
// The write puts a new value in the row every time. An update setting a
// column to what it already holds is matched and not written on MySQL and
// MariaDB, and a cluster certifies only rows that were written, so two runs
// applied on two nodes would both pass.
func (s *Store) Take(ctx context.Context, runID int64) error {
	if _, err := s.db.NewUpdate().Table("series").Set(`"taken_by" = ?`, rand.Text()).
		Where(`"id" = (SELECT "sr"."series_id" FROM "series_run" AS "sr" WHERE "sr"."id" = ?)`, runID).
		Exec(ctx); err != nil {
		return fmt.Errorf("take the series of run %d: %w", runID, err)
	}
	return nil
}

// ModulesOf is the repositories a run's checkout held, in the order the run
// named them.
func (s *Store) ModulesOf(ctx context.Context, runID int64) ([]Module, error) {
	var out []Module
	if err := s.db.NewSelect().Model(&out).
		Where(`"sm"."run_id" = ?`, runID).
		OrderExpr(`"sm"."id" ASC`).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the repositories run %d held: %w", runID, err)
	}
	return out, nil
}

// Modules records the repositories a run's checkout held.
func (s *Store) Modules(ctx context.Context, runID int64, modules []Module) error {
	if len(modules) == 0 {
		return nil
	}
	for i := range modules {
		modules[i].RunID = runID
	}
	if err := database.InBatchesUnkeyed(ctx, s.db, modules); err != nil {
		return fmt.Errorf("record the repositories run %d held: %w", runID, err)
	}
	return nil
}
