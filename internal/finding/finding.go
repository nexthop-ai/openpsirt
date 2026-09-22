package finding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// FixState is what upstream has done about an issue.
//
// The three mean different things to whoever is triaging: no fix existing yet,
// upstream having declined to fix it, and a fix being available are separate
// situations, and "upstream will not fix this" is a permanent condition that
// changes the outcome somebody should reach.
type FixState string

const (
	// NoFix means no fix is available.
	NoFix FixState = "none"
	// WontFix means upstream declined to fix it.
	WontFix FixState = "wont-fix"
	// FixedUpstream means a fixed version exists.
	FixedUpstream FixState = "fixed"
	// FixUnknown means the scanner did not say. It is its own answer rather
	// than folded into "no fix": reporting "upstream has released nothing" on
	// the strength of a scanner declining to answer is a claim about the world
	// made out of a gap in a report, and it is the claim a triager would act
	// on. Kept as a state so the rows are reachable — mapped to the empty
	// string, they belonged to no filter value and thirteen findings on the
	// reference image could not be listed by any of them.
	FixUnknown FixState = "unknown"
	// FixMixed is not a state a scan reports. It is what a *group* is where
	// its places disagree, which the list has to be able to say: the list
	// answers per issue and component across builds, and asking what upstream
	// did is asking about the whole group, so a group whose places differ has
	// no single answer. Without a word for it those rows matched no value at
	// all — the same hole the unknown state above was, one level up.
	FixMixed FixState = "mixed"
)

// agreedFixState is what a group's places say upstream did, or FixMixed where
// they do not agree.
//
// Read off both ends of the group rather than off a minimum: a minimum alone
// answers with one of the disagreeing values, so the filter selected the mixed
// set and every row it returned claimed a definite state.
func agreedFixState(least, most string) FixState {
	if least != most {
		return FixMixed
	}
	return FixState(least)
}

// agreedFixedIn is the version upstream fixed it in, or nothing where the
// group's places disagree about whether it did.
//
// Empty rather than the least of them: a version taken from one of two
// disagreeing rows is a fix version attached to a group that does not have one.
func agreedFixedIn(least, most, fixedIn string) string {
	if least != most {
		return ""
	}
	return fixedIn
}

// Closure says why a finding stopped being present.
//
// A finding that closes without a reason is a finding nobody can account for,
// and there is no volume at which "we cannot explain this" stops mattering.
type Closure string

const (
	// Removed means the component is no longer in the build at all.
	Removed Closure = "removed"
	// Upgraded means the component's upstream version moved.
	Upgraded Closure = "upgraded"
	// Revised means the shipped version changed while the upstream version did
	// not, which is what a carried patch looks like from the outside.
	Revised Closure = "revised"
	// Superseded means the component's version moved and the issue came with
	// it: this row closed, and the same issue is open against the new version.
	//
	// Told apart from Upgraded because they are opposite answers to "was this
	// fixed". Without it a bump that resolved nothing was recorded as a fix,
	// and the same issue appeared as fixed and as newly present in one
	// release comparison — a document that goes to customers.
	Superseded Closure = "superseded"
	// Unexplained means the component is present and unchanged and the scanner
	// stopped reporting it. It is always flagged and never suppressed.
	Unexplained Closure = "unexplained"
	// Invalid means the record should not have existed: this build never
	// shipped the thing, the entry named the wrong product, or it duplicates
	// an issue already tracked. The record is taken back rather than the world
	// having changed.
	//
	// It is the one closure on a different axis from the rest. Every other
	// answers "why did this stop being present"; this one says it was never
	// present, so it is neither a resolution nor a disappearance — it does not
	// count toward how fast things are fixed and it appears in no release
	// note, because there is nothing to tell a customer about a build that was
	// never affected.
	//
	// It never means the finding exists but does not apply here. That is
	// sayable already and properly: a triage decision of `not-applicable` with
	// the justification that fits, which a second person agrees to and which
	// exports as VEX. Letting this absorb that case would route dismissals
	// around approval entirely.
	Invalid Closure = "invalid"
	// Fixed means somebody said a flaw they recorded is fixed in this
	// build.
	//
	// The only closure a person writes, and it exists because nothing else
	// can write it: a run is the authority on what it found, and it never
	// found a flaw somebody recorded by hand, so the evidence every other
	// closure here rests on does not exist for this one.
	Fixed Closure = "fixed"
)

// Closures are every reason a finding stops being open, in the order they are
// offered.
//
// One list, as the sort orders are one list: the enum a caller sees is built
// from this rather than written out again, so a closure added here is
// published and one removed here is gone from the document too. It was a
// fourth hand-written copy of these seven words, and `Resolving` below records
// what the last three copies cost.
func Closures() []Closure {
	return []Closure{Removed, Upgraded, Revised, Superseded, Unexplained, Invalid, Fixed}
}

// Resolving is what counts as an issue actually going away.
//
// One list rather than three projections of it. It was a positive list of four
// words spliced into SQL, a negative list of three in Go, and a third list of
// the same four as a switch returning prose — none of them checked by the
// compiler, and all three disagreeing about any closure added later. A closure
// not named here is churn or a correction, never progress.
func Resolving() []Closure {
	return []Closure{Removed, Upgraded, Revised, Fixed}
}

// Resolves reports whether this closure is one of them.
func (c Closure) Resolves() bool {
	for _, each := range Resolving() {
		if c == each {
			return true
		}
	}
	return false
}

// Run is one execution of a scanner over one variant.
type Run struct {
	bun.BaseModel `bun:"table:scan_run,alias:sr"`

	ID       int64 `bun:"id,pk,autoincrement"`
	TargetID int64 `bun:"target_id,notnull"`
	// Scanner, ScannerVersion and DatabaseVersion are what produced this, and
	// RanHere says whether we ran it. Counts are only comparable between
	// products measured the same way, so a report that mixed the two without
	// saying would be a rumor rather than a report.
	Scanner         string     `bun:"scanner,notnull"`
	ScannerVersion  string     `bun:"scanner_version"`
	DatabaseVersion string     `bun:"database_version"`
	RanHere         bool       `bun:"ran_here,notnull"`
	StartedAt       time.Time  `bun:"started_at,notnull"`
	FinishedAt      *time.Time `bun:"finished_at"`
	Failure         string     `bun:"failure"`
	// Caution is what the scanner said while succeeding — a qualification on
	// the answer rather than a reason there is none. Kept apart from Failure
	// because a run that warned and a run that failed are different things,
	// and a column holding either would make them one.
	Caution string `bun:"caution"`
}

// Finding is a vulnerability at a place.
type Finding struct {
	bun.BaseModel `bun:"table:finding,alias:f"`

	ID              int64 `bun:"id,pk,autoincrement"`
	TargetID        int64 `bun:"target_id,notnull"`
	Kind            Kind  `bun:"kind,notnull"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
	// Visibility says whether this has been disclosed. A vulnerability a
	// scanner found in a shipped component is public knowledge by the time we
	// hear about it; what is not is a finding somebody entered here.
	Visibility  access.Visibility `bun:"visibility,notnull"`
	ComponentID int64             `bun:"component_id,notnull"`
	// ConsumerID is what pulled the component in. Empty where that is the
	// product itself: the root's name differs per variant, so keying on it
	// would break grouping the same finding across variants.
	ConsumerID *int64 `bun:"consumer_id"`
	// PlaceIdentity is the hashed pair of names. It is what a triage decision
	// is keyed on, so it is stored rather than derived — a decision has to be
	// findable without walking the graph of every variant it might reach.
	PlaceIdentity string   `bun:"place_identity,notnull"`
	FixState      FixState `bun:"fix_state"`
	FixedIn       string   `bun:"fixed_in"`
	// FixedAt is when that version became available. How long a fix has
	// existed is a different question from which version carries it, and it is
	// the one that says whether an upgrade is overdue or fresh.
	FixedAt *time.Time `bun:"fixed_at"`
	// DueAt is when this has to be answered by: when it was first seen,
	// plus how long something of this urgency may stay open. Stored rather
	// than derived — derived, it costs a pass over every open finding per
	// urgency band, since each band allows a different number of days.
	//
	// It is set when the finding opens and does not move as the finding
	// ages — nothing else would be a deadline. It is recounted on two
	// events, both of which make the stored answer wrong rather than
	// merely old: the policy that sets it changing, and the issue becoming
	// known to be exploited, which is the one signal that decides how long
	// there is. A recount runs from when the change was learned, never
	// from when the finding opened, or a fact arriving late would land a
	// deadline in the past.
	//
	// Null on a finding recorded before this was stored, which reads as
	// "not known" rather than "not due" — a finding with no deadline is
	// left out of what is running out rather than treated as overdue.
	DueAt *time.Time `bun:"due_at"`
	// SuppressedBy is the claim the build made that covers this, where it made
	// one. A covered finding is kept and marked rather than dropped: a finding
	// that simply stopped appearing is indistinguishable from a scanner fault,
	// and that is the bucket nothing is allowed to explain away.
	SuppressedBy *int64 `bun:"suppressed_by"`
	// Rank is how urgent this is, as one sortable number, and the flags beside
	// it are what it was made of that is not already on the row. The rest —
	// the likelihood and the score — belong to the issue and are read from
	// there.
	Urgency       int64 `bun:"urgency,notnull"`
	RankExploited bool  `bun:"urgency_exploited,notnull"`
	// RankExploitedHere is somebody here having recorded that this product was
	// attacked through the issue. Kept beside the flag above rather than
	// folded into it: a feed's word about the world and a person's word about
	// this product are different facts, and a report that names one of them
	// reads the column it means.
	RankExploitedHere bool `bun:"urgency_exploited_here,notnull"`
	// ExploitedLearnedAt is when exploitation was learned, which is what an
	// exploited deadline is counted from.
	//
	// The row carries it because nothing else does: a recount later has to
	// arrive at the same deadline the learning wrote, and counting from the
	// opening moves it back to a date that may already be in the past. Null
	// where the row is not exploited.
	ExploitedLearnedAt *time.Time `bun:"exploited_learned_at"`
	RankShipped        bool       `bun:"urgency_shipped,notnull"`
	// AssignedTo is who is dealing with this, and AssignedAt is when they were
	// given it. Absent means nobody, which is a state worth being able to ask
	// about rather than an empty column: work nobody owns is the thing that
	// falls between people.
	//
	// Held per finding rather than per group, because the rows are what
	// everything else is keyed on — but it is set for a whole group at once,
	// since assigning one place of an issue and not another is not something
	// anybody means to do.
	AssignedTo *int64     `bun:"assigned_to"`
	AssignedAt *time.Time `bun:"assigned_at"`
	// LastChangedAt is when anything about this finding last moved — a fix
	// appearing, or the build answering it. A finding open for years outlives
	// any record of the change kept elsewhere, so it carries its own.
	LastChangedAt time.Time `bun:"last_changed_at,notnull"`
	// ArrivedFrom is the upstream version this place held before, recorded
	// only where the version moved and the issue came with it. Its presence is
	// the statement that somebody bumped this and the bump did not resolve it;
	// its value is what they bumped from, so saying so needs no second query.
	ArrivedFrom string `bun:"arrived_from"`
	// MovedTo is the upstream version this place moved to, where moving is
	// what closed the finding. Set on close rather than worked out later: the
	// component that carried the issue is gone from the inventory by then, so
	// the pair of versions exists only while the scan is being applied — the
	// same reason ArrivedFrom is written on the way in.
	MovedTo string `bun:"moved_to"`
	// Matched says how the scanner reached this finding, and it is the
	// difference between "the people who package this said so" and "the
	// upstream version looks vulnerable and nobody has said otherwise".
	Matched Matched `bun:"matched"`
	// MatchedFrom is where this match came from, which is not always where the
	// issue is written up: one issue reached through two ecosystems has two
	// answers and the issue can hold only one. Empty where the scanner said
	// nothing.
	MatchedFrom string `bun:"matched_from"`
	// MatchedIn is which body of vulnerability data answered, as the scanner
	// names it — an ecosystem's own advisories against the national database's
	// identifiers. Finer than Matched, which is two words, and the difference
	// between the two is the whole of what a distribution's package needs
	// asking about.
	MatchedIn string `bun:"matched_in"`
	// MatchedRange is the version range the match fired on.
	//
	// The evidence for the judgment the match kind asks for rather than a
	// second way of making it: a range that names no packaging revision,
	// read beside a version that has one, is the whole argument in one
	// line. Recorded as the scanner wrote it and never parsed — comparing
	// a version against a range needs an ordering per ecosystem, which is
	// a different project.
	MatchedRange string `bun:"matched_range"`
	// DiscloseAt is when the embargo on this ends, on a finding nobody has
	// announced. Nil on a disclosed one, which is already public.
	//
	// Reaching it discloses nothing. Publishing embargoed detail because a
	// timer expired is the wrong default in both directions: if the fix is
	// not ready, disclosing anyway is a decision a person makes, and
	// automatic publication eventually publishes something nobody was
	// ready for. What the date does is escalate.
	DiscloseAt *time.Time `bun:"disclose_at"`
	// OpenedAt is when this became true. Carried here rather than reached
	// through the run, because not every finding has a run: one somebody
	// recorded by hand was opened by a person, and everything that asks when a
	// finding opened has to be able to answer for it.
	OpenedAt time.Time `bun:"opened_at,notnull"`
	// OpenedRunID is the run that opened it, where one did. Nil is a finding a
	// person opened.
	OpenedRunID *int64 `bun:"opened_run_id"`
	// ClosedAt is when it stopped being true, and nil is open. The same
	// separation the opening has, for the same reason and then one more: a run
	// closes nothing a person recorded — it is the authority on what it found,
	// and it found none of that — so with closure readable only through a run,
	// a finding somebody recorded by hand could never be closed at all.
	ClosedAt *time.Time `bun:"closed_at"`
	// ClosedRunID is the run that closed it and ClosedBy the person who did.
	// Exactly one of them is set on a closed finding: a scan closing what it
	// no longer sees, or somebody saying a flaw they recorded is fixed.
	ClosedRunID *int64 `bun:"closed_run_id"`
	ClosedBy    *int64 `bun:"closed_by"`
	// ClosedNote is why, where a person closed it. Required of them: a
	// closure with no reason is a record saying somebody closed it and
	// nothing else — and what is required is published, on the register
	// beside the category and the date, because the refusal is a promise to
	// whoever typed it that the sentence goes somewhere.
	ClosedNote    string  `bun:"closed_note"`
	ClosedBecause Closure `bun:"closed_because"`
}

// Reported is one issue a scanner reported against one component.
//
// It names a package at a version and stops there. Where that package sits is
// not something a scanner can know, because it never saw the graph.
type Reported struct {
	Issue     Named
	Component graph.Described
	FixState  FixState
	FixedIn   string
	// FixedAt is when the fixing version became available, where the report
	// says. "Fixed upstream fourteen months ago" is a different conversation
	// from "fixed in 0.17.0", and it is the one that decides whether an
	// upgrade is overdue or fresh.
	FixedAt *time.Time
	// Matched is how the scanner reached this, and MatchedFrom is where that
	// match came from. Kept because the two ways of reaching a finding mean
	// different things about a distribution's package.
	Matched      Matched
	MatchedFrom  string
	MatchedIn    string
	MatchedRange string
}

// Applied describes what a run changed.
type Applied struct {
	Opened int
	Closed int
	// Unexplained counts findings that closed with the component present and
	// unchanged. Always reported, never suppressed.
	Unexplained int
	// Updated counts findings that were already open and whose details moved —
	// a fix becoming available, or the build answering them. Somebody waiting
	// for a fix is waiting for exactly this.
	Updated int
	// Suppressed counts findings the build has already argued about. They are
	// open and visible; they are not work anybody has to do.
	Suppressed int
	// ClaimsReaching and ClaimsReachingNothing say how many of the build's
	// arguments landed on something it ships. One that reached nothing means a
	// finding the build believes it answered comes back as noise, and nothing
	// distinguishes that from a finding nobody has looked at.
	ClaimsReaching        int
	ClaimsReachingNothing int
	// Unplaced counts issues reported against something the target does not
	// contain. A report that does not match the inventory it was produced from
	// is worth seeing rather than quietly discarding.
	Unplaced int
}

// Unchanged reports whether the run changed nothing.
func (a Applied) Unchanged() bool { return a.Opened == 0 && a.Closed == 0 && a.Updated == 0 }

// PlaceIdentity keys a component under the thing that pulled it in.
//
// Names only, never versions: a version in the key would lapse every decision
// the next time anything was rebuilt. Where a component sits directly under
// the product, its name stands alone, because the product's name differs per
// variant and including it would stop the same place being recognized across
// them.
func PlaceIdentity(component, consumer string) string {
	basis := strings.TrimSpace(component)
	if c := strings.TrimSpace(consumer); c != "" {
		basis = c + "\x00" + basis
	}
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// Store records what runs find.
type Store struct {
	db bun.IDB
	// pool is the same handle where this store was built over one, and
	// nothing where it was built over a transaction.
	//
	// Kept for the one read that streams its rows rather than filling a
	// slice: bun hangs the row mapper off the pooled handle rather than off
	// the interface every other query here goes through. It is a read on the
	// export path, which is never inside somebody else's transaction.
	pool *bun.DB
	now  func() time.Time
	// reach is how many places in one build a routing rule's pattern may
	// name, or zero for the shipped number. Carried on the store so a test can
	// bring it down to a fixture rather than building a fixture up to it.
	reach int
	// afterReadingReport runs between a judgment reading the report and
	// writing to it, so a test can put another writer in that window. The
	// window is the whole of what the condition on the write is for, and
	// waiting for two callers to land in it by themselves is a test that
	// passes by not racing.
	afterReadingReport func()
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	pool, _ := database.Handle(db)
	return &Store{db: db, pool: pool, now: func() time.Time { return time.Now().UTC() }}
}

// Begin records that a scanner is about to run.
func (s *Store) Begin(ctx context.Context, run Run) (*Run, error) {
	run.StartedAt = s.now().Truncate(time.Microsecond)
	if _, err := s.db.NewInsert().Model(&run).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record the start of a scan run: %w", err)
	}
	return &run, nil
}

// Finish records that a run ended, what produced it, and why it went wrong if
// it did.
//
// The versions arrive here rather than at the start because they are the
// scanner's answer, not our question: what it says it is and what data it
// matched against are known once it has run. A finding that appeared or
// vanished because either moved is unexplainable without them.
func (s *Store) Finish(ctx context.Context, runID int64, version, databaseVersion,
	caution string, cause error) error {

	done := s.now().Truncate(time.Microsecond)
	failure := ""
	if cause != nil {
		failure = cause.Error()
	}
	_, err := s.db.NewUpdate().Model((*Run)(nil)).
		Set("finished_at = ?", done).Set("failure = ?", failure).
		Set("caution = ?", caution).
		Set("scanner_version = ?", version).Set("database_version = ?", databaseVersion).
		Where("id = ?", runID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("record the end of scan run %d: %w", runID, err)
	}
	return nil
}
