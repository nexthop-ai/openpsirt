// Package ingest decides what happens to a scan that arrives, and records it.
//
// The decisions here are about the scan's metadata rather than its contents:
// whether it is newer than what we already hold, whether we have seen this
// exact file before, and whether its timestamp is believable. Parsing is a
// separate concern and happens only for a scan that is accepted.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Status is what became of a scan.
type Status string

const (
	// Accepted means the scan was taken and is, or was, the current picture.
	Accepted Status = "accepted"
	// Failed means it was taken and could not be parsed. Recorded so a
	// producer sending unparseable files is visible rather than silent.
	Failed Status = "failed"
)

// Outcome is what an arriving scan should have happen to it.
type Outcome int

const (
	// Accept it: newer than what we hold, and not seen before.
	Accept Outcome = iota
	// AlreadyHave it: byte-for-byte what we already took. Report success
	// without doing the work again.
	AlreadyHave
	// NotNewer than the scan we already hold, so taking it would replace the
	// current picture with a stale one.
	NotNewer
	// BuiltInFuture, so its timestamp cannot be trusted.
	BuiltInFuture
)

// String names the outcome for logs and errors.
//
// Read by the refusals below and by the line the API writes when an upload is
// turned away. It was declared and reached by nothing, while those refusals
// spelled the same words inline — so the producer's words and this method's
// could drift, and the deployment logged nothing at all.
func (o Outcome) String() string {
	switch o {
	case Accept:
		return "accept"
	case AlreadyHave:
		return "already have"
	case NotNewer:
		return "not newer"
	case BuiltInFuture:
		return "built in the future"
	}
	return "unknown"
}

// futureTolerance is how far ahead of us a build time may be before we refuse
// it. Clocks disagree by seconds; a few minutes covers that without accepting
// a date that would wedge the target.
const futureTolerance = 5 * time.Minute

// storedPrecision is the finest resolution every supported database keeps.
//
// Go carries nanoseconds and no engine here stores them, so a value written
// and read back is slightly older than the one still in memory. The ordering
// comparison then reports a scan as newer than itself, and a second file
// claiming the same build time is accepted when it should not be. Rounding to
// what the database will actually keep, before comparing or storing, makes the
// two agree.
const storedPrecision = time.Microsecond

// asStored rounds a time to what the database will keep, in UTC.
func asStored(t time.Time) time.Time { return t.UTC().Truncate(storedPrecision) }

// ErrRejected is returned for any arriving scan we decline to take.
var ErrRejected = errors.New("scan rejected")

// ErrNoScan is returned when something names a scan that is not there.
var ErrNoScan = errors.New("no such scan")

// Arriving describes a scan someone is trying to send us.
type Arriving struct {
	// TargetID is the already-resolved target.
	TargetID int64
	// ContentHash is the hex digest of the file exactly as received.
	ContentHash string
	// BuiltAt is when the producer says the scan was made. This orders scans,
	// not the time we happened to receive them: uploads retry, transfer slowly
	// and queue, so arrival order says nothing about which is newer.
	BuiltAt time.Time
	// Serial is the identity the document carries for itself, which is what
	// joins anything produced from it back to it.
	Serial string
	// ParserVersion is the version of the code that will read it.
	ParserVersion string
	// Credential identifies what sent it. Blank until sign-in exists.
	Credential string
}

// Scan is a scan we took.
type Scan struct {
	bun.BaseModel `bun:"table:scan,alias:sc"`

	ID            int64     `bun:"id,pk,autoincrement"`
	TargetID      int64     `bun:"target_id,notnull"`
	ContentHash   string    `bun:"content_hash,notnull"`
	Serial        string    `bun:"serial"`
	BuiltAt       time.Time `bun:"built_at,notnull"`
	ReceivedAt    time.Time `bun:"received_at,notnull"`
	ParserVersion string    `bun:"parser_version,notnull"`
	Credential    string    `bun:"credential"`
	Status        Status    `bun:"status,notnull"`
	// Failure says why a scan that was taken could not be read. Empty until
	// something goes wrong, which is most of the time.
	Failure string `bun:"failure"`
	// Components and Placed are what the inventory was made of, written when
	// it is read. Nil until then, and on anything recorded before they were
	// kept — which reads as "not known" rather than as none.
	//
	// The pair is the point. One component nothing places is ordinary; a
	// document that places none of them is a list rather than a graph, and
	// every finding it produces will be individually correct and unable to say
	// why it is there. Nothing else on a receipt distinguishes the two.
	Components *int `bun:"components"`
	Placed     *int `bun:"placed"`
}

// Store records scans and answers what to do with a new one.
type Store struct {
	db bun.IDB
	// now is overridable so tests can place a build time relative to a fixed
	// point rather than to the wall clock.
	now func() time.Time
}

// DB exposes the underlying handle for queries this package does not wrap.
func (s *Store) DB() bun.IDB { return s.db }

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Decide says what should happen to an arriving scan, without recording
// anything.
//
// The order of these checks matters. A future build time is refused first,
// because accepting one would mean nothing legitimate could ever be newer and
// the target would take no further scans. A file we already hold is next, so a
// retry after a timeout that actually succeeded reports success rather than
// failing the pipeline for work that landed. Only then does age matter.
func (s *Store) Decide(ctx context.Context, a Arriving) (Outcome, error) {
	built := asStored(a.BuiltAt)
	if built.After(s.now().Add(futureTolerance)) {
		return BuiltInFuture, nil
	}

	seen, err := s.byContent(ctx, a.TargetID, a.ContentHash)
	if err != nil {
		return Accept, err
	}
	if seen != nil {
		return AlreadyHave, nil
	}

	newest, err := s.Newest(ctx, a.TargetID)
	if err != nil {
		return Accept, err
	}
	if newest != nil && !built.After(asStored(newest.BuiltAt)) {
		return NotNewer, nil
	}
	return Accept, nil
}

// Record decides and, when the answer is to take it, writes the scan.
//
// The returned scan is the one now current for that variant: for a file we
// already hold, that is the row we took the first time.
func (s *Store) Record(ctx context.Context, a Arriving) (*Scan, Outcome, error) {
	outcome, err := s.Decide(ctx, a)
	if err != nil {
		return nil, outcome, err
	}

	switch outcome {
	case AlreadyHave:
		existing, err := s.byContent(ctx, a.TargetID, a.ContentHash)
		return existing, AlreadyHave, err

	case NotNewer:
		// What is already here, which is the whole content of the refusal. A
		// read that failed is not "none": telling a producer their build holds
		// no scan, in the sentence refusing the one they just sent, is the
		// most confusing answer available.
		newest, err := s.Newest(ctx, a.TargetID)
		if err != nil {
			return nil, NotNewer, fmt.Errorf(
				"read what this variant already holds: %w", err)
		}
		held := "none"
		if newest != nil {
			held = newest.BuiltAt.Format(time.RFC3339Nano)
		}
		return nil, NotNewer, fmt.Errorf(
			"%w (%s): built %s, but this variant already holds a scan built %s",
			ErrRejected, NotNewer, a.BuiltAt.Format(time.RFC3339Nano), held)

	case BuiltInFuture:
		return nil, BuiltInFuture, fmt.Errorf(
			"%w (%s): built %s, which is ahead of this server's clock. "+
				"Accepting it would mean no later scan is ever newer",
			ErrRejected, BuiltInFuture, a.BuiltAt.Format(time.RFC3339Nano))
	}

	scan := &Scan{
		TargetID:      a.TargetID,
		ContentHash:   a.ContentHash,
		Serial:        a.Serial,
		BuiltAt:       asStored(a.BuiltAt),
		ReceivedAt:    s.now().Truncate(time.Microsecond),
		ParserVersion: a.ParserVersion,
		Credential:    a.Credential,
		Status:        Accepted,
	}
	if _, err := s.db.NewInsert().Model(scan).Exec(ctx); err != nil {
		// Two uploads of one file can both pass the check and race to write.
		// The loser sees the unique constraint, which means the other landed
		// — the same situation as sending it twice, and answered the same way
		// rather than as a failure the producer would retry into a red build.
		if existing, found := s.byContent(ctx, a.TargetID, a.ContentHash); found == nil && existing != nil {
			return existing, AlreadyHave, nil
		}
		return nil, Accept, fmt.Errorf("record scan: %w", err)
	}
	return scan, Accept, nil
}

// Newest returns the most recently built accepted scan for a variant, or nil.
func (s *Store) Newest(ctx context.Context, targetID int64) (*Scan, error) {
	scan := new(Scan)
	err := s.db.NewSelect().Model(scan).
		Where("target_id = ?", targetID).
		Where("status = ?", Accepted).
		Order("built_at DESC").
		Limit(1).
		Scan(ctx)
	if err != nil {
		if database.IsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return scan, nil
}

func (s *Store) byContent(ctx context.Context, targetID int64, hash string) (*Scan, error) {
	scan := new(Scan)
	err := s.db.NewSelect().Model(scan).
		Where("target_id = ?", targetID).
		Where("content_hash = ?", hash).
		Scan(ctx)
	if err != nil {
		if database.IsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return scan, nil
}

// ByID reads back a scan.
func (s *Store) ByID(ctx context.Context, id int64) (*Scan, error) {
	var scan Scan
	if err := s.db.NewSelect().Model(&scan).Where("id = ?", id).Scan(ctx); err != nil {
		return nil, fmt.Errorf("%w: %d: %w", ErrNoScan, id, err)
	}
	return &scan, nil
}

// MarkFailed records that a scan was taken and could not be read.
//
// The reason is kept with it. A producer sending files nothing can read needs
// to be visible as exactly that, rather than as a scan that was accepted and
// then quietly did nothing.
func (s *Store) MarkFailed(ctx context.Context, id int64, cause error) error {
	reason := ""
	if cause != nil {
		reason = cause.Error()
	}
	_, err := s.db.NewUpdate().Model((*Scan)(nil)).
		Set("status = ?", Failed).
		Set("failure = ?", truncate(reason, 2000)).
		Where("id = ?", id).Exec(ctx)
	if err != nil {
		return fmt.Errorf("record that scan %d failed: %w", id, err)
	}
	return nil
}

// truncate bounds what is stored from a message that quotes a scan file.
//
// Cut on a rune boundary. A message quoting a producer's own text can carry
// multi-byte characters, and a slice through one of them leaves invalid
// UTF-8: PostgreSQL refuses it outright and MySQL and MariaDB refuse it in
// strict mode, so recording why a scan failed failed — leaving the scan
// accepted, with nothing saying why nothing happened. SQLite stores it
// happily, so the quick loop never sees it.
func truncate(s string, most int) string {
	if len(s) <= most {
		return s
	}
	cut := s[:most]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// Made records what an inventory turned out to be made of.
//
// Written after it has been read rather than when it arrives, because until
// then nobody knows: an upload is bytes, and how many components it describes
// and how many of them anything places are answers the parser produces.
func (s *Store) Made(ctx context.Context, scanID int64, components, placed int) error {
	_, err := s.db.NewUpdate().Model((*Scan)(nil)).
		Set("components = ?", components).
		Set("placed = ?", placed).
		Where("id = ?", scanID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("record what the inventory was made of: %w", err)
	}
	return nil
}
