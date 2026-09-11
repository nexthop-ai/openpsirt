package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// Decision is one claim about one combination of code.
type Decision struct {
	bun.BaseModel `bun:"table:decision,alias:de"`

	ID int64 `bun:"id,pk,autoincrement"`
	// ClaimID is the action this row was written by, which is what the
	// queue lists and what an approver agrees to.
	ClaimID int64 `bun:"claim_id,notnull"`
	// FromStatement is the VEX statement this was started from, where one
	// was. A citation and never an application: what a publisher said is
	// not our judgment, and what this records is that somebody read it
	// before making theirs — which is what lets anything notice that the
	// ground moved under an approved dismissal.
	FromStatement   *int64            `bun:"from_statement_id"`
	ProductID       int64             `bun:"product_id,notnull"`
	VulnerabilityID int64             `bun:"vulnerability_id,notnull"`
	PlaceIdentity   string            `bun:"place_identity,notnull"`
	Visibility      access.Visibility `bun:"visibility,notnull"`
	// The versions the claim was made against. Absent where nothing states
	// one, and absent for the consumer where the thing above is the product
	// itself — whose version changes every build and is excluded from expiry.
	ComponentUpstreamVersion *string `bun:"component_upstream_version"`
	ConsumerUpstreamVersion  *string `bun:"consumer_upstream_version"`
	// What the claim says is on the claim: the outcome, the justification, the
	// mitigation, the dates, the version an upgrade moves to. One act is one
	// argument, and a copy per place is a copy that can be revised on its own.
	//
	// SeverityCenti is how bad this was judged to be when the claim was made,
	// in hundredths. Kept with the decision rather than read from the issue
	// later, because what a re-affirmation asks is whether severity has risen
	// *since* — and an issue's severity is rewritten in place as reports
	// revise it, so reading it now would compare a number against itself.
	SeverityCenti *int `bun:"severity_centi"`
	// NeedsApproval says a second person has to agree before this takes
	// effect. A short deferral does not, so it is a property of the claim
	// rather than of its outcome alone — and it has to be recorded, or a claim
	// that is waiting and one that is in force are indistinguishable.
	NeedsApproval bool  `bun:"needs_approval,notnull"`
	State         State `bun:"state,notnull"`
	// SentBackAt marks that an approver asked for more before they would
	// agree, and is cleared when the author revises. Deliberately not a state:
	// the claim is still proposed and still suppresses nothing, and what
	// changed is whose turn it is.
	SentBackAt *time.Time `bun:"sent_back_at"`
	// SelectedBy is how the set this was part of was narrowed, for a claim
	// recorded as one of many in a single action. Null for a claim made on
	// its own — and never the claim itself: "these matched a word" is how a
	// candidate was found, not a reason anybody would accept.
	SelectedBy *string   `bun:"selected_by"`
	ProposedBy int64     `bun:"proposed_by,notnull"`
	ProposedAt time.Time `bun:"proposed_at,notnull"`
	// EndedAt is when this stopped applying — withdrawn, or lapsed because
	// the code moved. Null while it is live.
	EndedAt *time.Time `bun:"ended_at"`
	// LiveKey is what this decision is a claim about, while it is still a live
	// claim. Null once it is withdrawn or has lapsed, which is what lets a
	// fresh claim be made at a place a dead one used to cover.
	LiveKey *string `bun:"live_key"`
	// Claim is the argument this row applies — the outcome, the justification,
	// the dates, the version an upgrade moves to.
	//
	// Loaded by a query that asks for it and nil in one that did not, which is
	// deliberate: plenty of readers want only where a judgment lands and when
	// it stops applying, and a zero-valued argument standing in for one nobody
	// fetched would read as an outcome nobody chose.
	Claim *Claim `bun:"rel:belongs-to,join:claim_id=id"`
}

// Revision is one statement of the reasoning behind a claim.
//
// Hung off the claim rather than off its rows, because one act is one
// argument. A copy per place is a copy that can be revised on its own, which
// left forty-three rows saying the old thing under a claim that read as agreed.
type Revision struct {
	bun.BaseModel `bun:"table:claim_revision,alias:dr"`

	ID        int64     `bun:"id,pk,autoincrement"`
	ClaimID   int64     `bun:"claim_id,notnull"`
	Ordinal   int64     `bun:"ordinal,notnull"`
	Body      string    `bun:"body,notnull"`
	WrittenBy int64     `bun:"written_by,notnull"`
	WrittenAt time.Time `bun:"written_at,notnull"`
}

// Approval is a second person agreeing to one revision of a claim's reasoning.
type Approval struct {
	bun.BaseModel `bun:"table:claim_approval,alias:da"`

	ID          int64      `bun:"id,pk,autoincrement"`
	ClaimID     int64      `bun:"claim_id,notnull"`
	RevisionID  int64      `bun:"revision_id,notnull"`
	ApprovedBy  int64      `bun:"approved_by,notnull"`
	ApprovedAt  time.Time  `bun:"approved_at,notnull"`
	WithdrawnAt *time.Time `bun:"withdrawn_at"`
	Batch       *string    `bun:"batch"`
	// Covered is how many findings this claim covered when it was agreed to.
	//
	// Kept rather than worked out later. A decision reaches by matching, so a
	// build appearing afterwards is covered without anybody acting — asking
	// what it covers *now* answers a different question from what somebody
	// consented to, and only one of those two can be recovered after the fact.
	Covered *int `bun:"covered"`
	// CarriedFrom names the agreement this one was carried forward from,
	// where it was carried rather than given.
	//
	// A re-affirmation states fresh reasoning and stands on the agreement its
	// predecessor had. Recorded as an ordinary approval that read as the
	// earlier approver agreeing, today, to words they have never seen — which
	// is what an approval naming one revision of the reasoning exists to make
	// impossible. What is true is that they agreed to the earlier words, and
	// this is what says so.
	CarriedFrom *int64 `bun:"carried_from"`
}

// Place is what a decision is a claim about, as a finding presents it.
//
// Assembled from the finding and the components it points at rather than from
// anything a person typed, so that whether a decision applies is a question
// about the code and not about how somebody described it.
type Place struct {
	ProductID       int64
	VulnerabilityID int64
	PlaceIdentity   string
	// Visibility is the finding's, carried here so that what somebody may
	// decide about is answered where the query is rather than by whichever
	// handler happened to build this. A finding nobody has disclosed is one
	// only a private triager may argue about.
	Visibility access.Visibility
	// OnTag says this sits in a release that was built once and cannot change.
	// Read from the finding rather than supplied, for the same reason the
	// visibility is: what may be said about a place is a fact about the place.
	OnTag bool
	// ComponentUpstream and ConsumerUpstream are the versions expiry compares.
	// They are the *upstream* versions: a shipped package carries a version of
	// its own that moves whenever it is rebuilt, and rebuilding is not a
	// reason to ask somebody the same question again.
	ComponentUpstream string
	ConsumerUpstream  string
}

// ErrNotTheirs is returned when somebody reaches for a decision about a
// product they may not triage.
//
// The same answer whether the product is one they cannot see or one they can
// only read: telling those apart would say which products exist to somebody
// who was told they may not ask.
var ErrNotTheirs = errors.New("not authorized")

// mayDecide is whether a subject may argue about findings of this visibility
// here, in the shape the narrowing rules take.
//
// A thin name over the subject's own answer, because the rules beside it are
// passed around as functions of this signature — and the rule itself lives on
// the subject, where every package asking it can reach one copy.
func mayDecide(subject access.Subject, productID int64, visibility access.Visibility) bool {
	return subject.Triages(visibility, productID)
}

// mayDecideOn is the same question about one named issue, which is what a
// collaborator was brought into.
//
// Separate from mayDecide rather than another argument to it, because the two
// are asked at different units: "may they decide in this product" is a
// question about a product and has no issue to name, and every caller that has
// one is arguing about that one issue.
//
// It never widens approving. mayApprove is built on mayDecide and stays there:
// two collaborators could otherwise satisfy the two people a dismissal on an
// embargoed finding asks for, with nobody accountable for the product.
func mayDecideOn(subject access.Subject, productID, vulnerabilityID int64,
	visibility access.Visibility) bool {

	return mayDecide(subject, productID, visibility) ||
		subject.OnCase(productID, vulnerabilityID)
}

// mayApprove reports whether a subject may agree to somebody else's claim.
//
// Approving is not deciding, and requiring the triage role for it made the
// approver capability decorative: somebody granted exactly the right to
// approve could not approve anything. It is a capability rather than a grant
// of visibility, so it is asked alongside whether they may read the finding —
// otherwise handing somebody the ability to approve hands them everything
// there is to approve.
//
// A triager may also approve, on somebody else's claim. Two triagers agreeing
// to each other's work is the ordinary shape of a small team, and the control
// that matters is that the two are different people — which is checked
// separately and has no override.
func mayApprove(subject access.Subject, productID int64, visibility access.Visibility) bool {
	if subject.Kind != access.Person {
		return false
	}
	if !subject.Reads(visibility, productID) {
		return false
	}
	return subject.Holds(access.Approver, productID) || mayDecide(subject, productID, visibility)
}

// ErrSamePerson is returned when somebody tries to approve their own claim.
var ErrSamePerson = errors.New("the person who proposed a decision may not approve it")

// ErrNothingToApprove is returned when there is no current reasoning to
// approve, which means the decision is not in a state anybody can agree to.
var ErrNothingToApprove = errors.New("that decision has no reasoning to approve")

// Store reads and writes decisions.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Proposal is somebody claiming something about a finding.
type Proposal struct {
	Place         Place
	Outcome       Outcome
	Justification Justification
	// Mitigation names the thing that stops it — the rule, the setting,
	// the service that is not exposed. Required where the justification is
	// that mitigations already exist, because that claim rests on
	// configuration rather than on code, and configuration can be removed
	// with no version moving and nothing asking again.
	Mitigation    string
	DeferredUntil *time.Time
	// FixedVersion is the package version whoever packages this states the
	// fix arrived in. Required where the claim is that the fix is already
	// here, because that claim is a fact somebody can check against the
	// packager's own record rather than a judgment — and a claim of that
	// kind with nothing to check is the one to be most careful of.
	FixedVersion string
	// CommittedTo is when the work promised here will be done, for the two
	// outcomes that promise something. Not a deferral's date: that says
	// when somebody will look again, and this says when the thing will
	// have happened — after which the scans say whether it did.
	CommittedTo *time.Time
	// UpgradeTo is the version an upgrade moves to, where that is the action.
	// It is the payload of the claim rather than a second record beside it,
	// so what a person decided and what the release is waiting on cannot come
	// to disagree.
	UpgradeTo string
	// Binding is the earliest deadline among the findings this act covers.
	//
	// What the commitment is gated against. Inside it, promising to act by a
	// date is ordinary triage — the work is already allowed to stay open that
	// long. Past it, the promise is a deferral of the worst thing the act
	// covers, and a second person agrees. Computed over the whole set by the
	// caller, because one act covering a critical and a medium is gated by
	// the critical however many mediums are in it.
	Binding   *time.Time
	Reasoning string
	By        int64
	// SeverityCenti is how bad this is judged to be right now, in hundredths.
	// Recorded with the claim so that a later re-affirmation can ask whether
	// it has risen since.
	SeverityCenti int
	// SelectedBy is how the set was narrowed, where this is one of many
	// recorded together. Recorded with the claim so that "how were these
	// chosen" has an answer later.
	SelectedBy string
	// FromStatement is the VEX statement this was started from, where one
	// was. Recorded so that a revision to it can be noticed; it is never
	// what the claim rests on, which is the reasoning somebody typed.
	FromStatement *int64
	// NeedsApproval says a second person must agree before this takes effect.
	//
	// **Worked out by the store, inside the transaction that writes.** Not
	// something whoever is proposing states: it turns on the deployment's
	// threshold and on what this place has already been put off for, and read
	// before the transaction opened it described a world that a retry — or a
	// policy somebody changed in between — has left behind. The acts that are
	// gated by construction rather than by arithmetic set it themselves and
	// say why.
	NeedsApproval bool
}

// Propose records a claim and the reasoning behind it.
//
// The two are written together. A claim with no reasoning is not something a
// second person can agree to, and leaving the reasoning to a later write is
// how a decision ends up in the queue with nothing in it to review.
func (s *Store) Propose(ctx context.Context, subject access.Subject, p Proposal) (*Decision, error) {
	// Normalized before it is checked, not only before it is stored. Checking
	// the stated value and storing the careful one would let a place that
	// states nothing pass the check for disclosed findings and then be
	// recorded as undisclosed — authorized as one thing and kept as another.
	if !mayDecideOn(subject, p.Place.ProductID, p.Place.VulnerabilityID, visibilityOf(p.Place)) {
		return nil, ErrNotTheirs
	}
	if err := p.valid(s.now()); err != nil {
		return nil, err
	}
	if p.By != subject.ID {
		// A claim is somebody's, and recording it under another name would
		// make the second-person rule meaningless: anybody could propose as
		// somebody else and then agree with themselves.
		return nil, fmt.Errorf("a decision is recorded as made by whoever made it")
	}

	db, ok := s.db.(*bun.DB)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}

	var recorded *Decision
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		// Worked out here rather than taken from the caller, and re-worked on
		// every attempt: what it turns on is the policy and what this place
		// has already been put off for, both of which a retry re-reads.
		gated := []Proposal{p}
		if err := within.gate(ctx, gated); err != nil {
			return err
		}
		claim, err := within.newClaim(ctx, FindingClaim, p.By, nil, "", gated[0])
		if err != nil {
			return err
		}
		recorded, err = within.propose(ctx, claim, gated[0])
		return err
	})
	if err != nil {
		return recorded, s.alreadyDecided(ctx, err, []Place{p.Place})
	}
	return recorded, nil
}

// ProposeMany records the same claim at several places as one action.
//
// One judgment about a finding covers every place it sits at unless somebody
// narrows it, and a finding on shared code reaches many: on a real image a
// kernel issue averages eighty-six. Written one at a time that is eighty-six
// transactions, each with its own commit, and on SQLite — held to a single
// connection because it has one writer — that is the whole process waiting
// while somebody presses a button.
//
// Atomic for a better reason than speed. grouping as presentation only has one
// action writing one record per place; half of them written and the rest
// abandoned is not that, and it leaves a finding that is neither answered nor
// open with nothing saying which places were which. The same holds across
// builds, where one judgment covers a place in each of several.
func (s *Store) ProposeMany(ctx context.Context, subject access.Subject, proposals []Proposal,
	cap int) ([]*Decision, error) {

	if len(proposals) == 0 {
		return nil, nil
	}
	if err := allowed(subject, proposals, cap, s.now()); err != nil {
		return nil, err
	}
	if err := oneArgument(proposals); err != nil {
		return nil, err
	}

	db, ok := s.db.(*bun.DB)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}

	var recorded []*Decision
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		recorded = recorded[:0]
		// Asked per place rather than once for the set: the threshold reads
		// the claim, and two places of one finding can differ in what they
		// carry. Re-worked on every attempt, against the policy and the
		// postponement in force when the write lands rather than when the
		// request arrived.
		if err := within.gate(ctx, proposals); err != nil {
			return err
		}
		// One action, one claim, however many places it covers. The
		// claim is what the queue lists, what an approver agrees to, and what
		// the argument is held on; the rows underneath stay one per place and
		// carry only where the judgment lands.
		claim, err := within.newClaim(ctx, FindingClaim, subject.ID, nil, "", proposals[0])
		if err != nil {
			return err
		}
		recorded, err = within.proposeAll(ctx, claim, proposals)
		return err
	})
	if err != nil {
		return nil, s.alreadyDecided(ctx, err, placesOf(proposals))
	}
	return recorded, nil
}

func (s *Store) propose(ctx context.Context, claim *Claim, p Proposal) (*Decision, error) {
	written, err := s.proposeAll(ctx, claim, []Proposal{p})
	if err != nil {
		return nil, err
	}
	return written[0], nil
}

// proposeAll writes one row per place, in batches rather than one at a time.
//
// One judgment covers every place it sits at, and on shared code that is many:
// 507 places for the worst case on the demo. A round trip each is 1.4 s on
// MySQL where the batched form is one statement per five hundred rows — the
// same shape the scan apply already uses, and for the same reason.
func (s *Store) proposeAll(ctx context.Context, claim *Claim, proposals []Proposal) ([]*Decision, error) {
	now := s.now().Truncate(time.Microsecond)
	rows := make([]Decision, 0, len(proposals))
	for _, p := range proposals {
		rows = append(rows, s.row(claim, p, now))
	}
	if err := database.InBatches(ctx, s.db, rows); err != nil {
		if database.IsDuplicate(err) {
			// The unique index over the live key refused it, which is the only
			// thing that could: two proposals arriving together both walk
			// through any check made before the write. Naming the claim that
			// is already there happens outside this transaction — a failed
			// write leaves nothing else in it able to read.
			return nil, ErrAlreadyDecided
		}
		return nil, fmt.Errorf("record %d decisions: %w", len(rows), err)
	}
	written := make([]*Decision, 0, len(rows))
	for i := range rows {
		written = append(written, &rows[i])
	}
	return written, nil
}

// row is one decision as it will be stored: where the judgment lands, and
// nothing about what it says.
func (s *Store) row(claim *Claim, p Proposal, now time.Time) Decision {
	key := liveKeyFor(p.Place)
	liveKey := &key
	decision := Decision{
		ClaimID: claim.ID,
		// Carried on the row that was just written, because what a caller
		// renders is the judgment and the judgment is the claim's.
		Claim:     claim,
		ProductID: p.Place.ProductID, VulnerabilityID: p.Place.VulnerabilityID,
		PlaceIdentity:            p.Place.PlaceIdentity,
		Visibility:               visibilityOf(p.Place),
		ComponentUpstreamVersion: text(p.Place.ComponentUpstream),
		ConsumerUpstreamVersion:  text(p.Place.ConsumerUpstream),
		State:                    Proposed,
		NeedsApproval:            p.NeedsApproval,
		FromStatement:            p.FromStatement,
		LiveKey:                  liveKey,
		ProposedBy:               p.By, ProposedAt: now,
	}
	if p.SeverityCenti > 0 {
		judged := p.SeverityCenti
		decision.SeverityCenti = &judged
	}
	if p.SelectedBy != "" {
		how := p.SelectedBy
		decision.SelectedBy = &how
	}
	return decision
}

// oneArgument refuses a set of proposals that do not all say the same thing.
//
// One action is one argument. The caller assembles a proposal per place because
// what varies per place — the versions it was made against, whether a second
// person has to agree, how bad it was judged to be — has to come from the row
// rather than from whoever pressed the button. What the claim *says* does not
// vary, and nothing has ever produced a set where it did: in the measured
// deployment every payload field was constant across every row of every claim.
//
// Refused rather than quietly taking the first, because a set that disagrees is
// two claims somebody meant to record as one, and recording it as one loses
// whichever half was not the first.
func oneArgument(proposals []Proposal) error {
	first := proposals[0]
	for _, p := range proposals[1:] {
		switch {
		case p.Outcome != first.Outcome:
			return fmt.Errorf("one action records one outcome: %q and %q were both given",
				first.Outcome, p.Outcome)
		case p.Justification != first.Justification:
			return errors.New("one action records one justification")
		case strings.TrimSpace(p.Mitigation) != strings.TrimSpace(first.Mitigation):
			return errors.New("one action records one mitigation")
		case version(p.FixedVersion) != version(first.FixedVersion):
			return errors.New("one action records one fixed version")
		case version(p.UpgradeTo) != version(first.UpgradeTo):
			return errors.New("one action records one version to upgrade to")
		case !sameDay(p.DeferredUntil, first.DeferredUntil):
			return errors.New("one action records one date to look again")
		case !sameDay(p.CommittedTo, first.CommittedTo):
			return errors.New("one action records one date to act by")
		case strings.TrimSpace(p.Reasoning) != strings.TrimSpace(first.Reasoning):
			return errors.New("one action records one piece of reasoning")
		}
	}
	return nil
}

// sameDay compares two dates either of which may be absent.
func sameDay(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

// valid reports whether a proposal says enough to be recorded.
//
// It takes the moment rather than reading a clock, because a store's clock is
// injectable and a rule about dates that read a different clock from the rest
// of the package would be a rule no test could pin.
func (p Proposal) valid(now time.Time) error {
	if !p.Outcome.Valid() {
		return fmt.Errorf("%q is not an outcome", p.Outcome)
	}
	// **A tag cannot be fixed.** It was built once and is what somebody
	// received, so an outcome that names a date is a statement about a thing
	// that will not move: a deferral says somebody will look again when
	// nothing will have changed, and a promise to act says work will land in a
	// release that is closed.
	//
	// The three refused are exactly the three that store a date, so this is
	// one question rather than a list to keep in step. It is not Commits: a
	// deferral's date is a review date rather than a commitment, and it is as
	// meaningless here as the other two.
	//
	// What can still be said about a tag is what is true of it — affected, not
	// applicable, will not fix, already fixed here — which is the whole point
	// of triaging one.
	if p.Place.OnTag && p.Outcome.Dated() {
		return fmt.Errorf(
			"%q names a date, and this release was built once: it cannot change, so nothing "+
				"can be promised about it. Say what is true of it instead", p.Outcome)
	}
	if strings.TrimSpace(p.Reasoning) == "" {
		return errors.New("a decision needs reasoning, because somebody else has to agree with it")
	}
	// The same policy every other typed field goes through, run before the
	// text is stored rather than when it is read back. Stored text is then
	// known to have passed what was in force when it arrived.
	if err := markdown.Check(p.Reasoning); err != nil {
		return err
	}
	if p.By == 0 {
		return errors.New("a decision needs somebody to have made it")
	}
	if err := keyable(p.Place); err != nil {
		return err
	}
	// The claim that something does not affect us *is* which of the
	// recognized reasons applies, so it is not optional there — and it is
	// meaningless on the others, which are claims about priority rather than
	// about applicability.
	switch p.Outcome {
	case NotApplicable:
		if !p.Justification.Valid() {
			return fmt.Errorf("%q is not a recognized reason for something not applying", p.Justification)
		}
		// Named, because the tool cannot notice this one going away.
		// Every other reason is a claim about code and lapses when the
		// code moves; this one is a claim about configuration, which
		// can be removed with nothing moving at all.
		if p.Justification == MitigationsExist && strings.TrimSpace(p.Mitigation) == "" {
			return errors.New(
				"say what stops it — a claim that mitigations already exist is about " +
					"configuration rather than code, so nothing here will notice it being " +
					"removed and the next person needs to know what to go and check")
		}
	}
	if p.Justification != MitigationsExist && strings.TrimSpace(p.Mitigation) != "" {
		return fmt.Errorf("naming what stops it belongs to %q and no other reason",
			MitigationsExist)
	}
	switch p.Outcome {
	case NotApplicable:
	default:
		if p.Justification != "" {
			return fmt.Errorf("%q states why something does not apply, which %q does not claim",
				p.Justification, p.Outcome)
		}
	}
	if p.Outcome == Deferred && p.DeferredUntil == nil {
		return errors.New("a deferral needs a date it returns on, or it is a decision never to look again")
	}
	if p.Outcome != Deferred && p.DeferredUntil != nil {
		return fmt.Errorf("%q does not return on a date", p.Outcome)
	}
	// The version the fix arrived in is what makes this claim checkable
	// against whoever packages it. Without it the claim is "trust me",
	// which is the one thing this outcome must not be able to say.
	//
	// It is recorded and never compared against what ships. Deciding
	// whether one version is at or past another needs an ordering per
	// ecosystem — Debian epochs, RPM release segments, and the ecosystems
	// that follow neither — which is a different project entirely.
	if p.Outcome == AlreadyFixed && strings.TrimSpace(p.FixedVersion) == "" {
		return errors.New("a claim that the fix is already here needs the version it arrived in, so somebody can check it")
	}
	if p.Outcome != AlreadyFixed && strings.TrimSpace(p.FixedVersion) != "" {
		return fmt.Errorf("%q does not claim a fix has arrived", p.Outcome)
	}
	// The two outcomes that promise work need the date the work lands .
	// Without it there is nothing to gate against and nothing to lapse —
	// the claim would be "we will deal with this", which is what leaving a
	// finding undecided already says.
	if p.Outcome.Commits() && p.CommittedTo == nil {
		return fmt.Errorf("%q promises work and needs the date it will be done, "+
			"or it says nothing a finding left alone does not", p.Outcome)
	}
	if !p.Outcome.Commits() && p.CommittedTo != nil {
		return fmt.Errorf("%q promises no work, so there is no date for it to land on", p.Outcome)
	}
	// **A date already past is not a date.** Nothing here checked, and the two
	// dates fail in opposite directions: a deferral until last year takes the
	// place's live key so nobody else may decide there, suppresses nothing,
	// and lands in the review queue already run out — a work item the tool
	// made for itself. A promise to act by last year is worse, because the
	// gate asks whether the date is past the deadline the work has and a date
	// in the past never is, so the promise stands on one signature.
	if p.DeferredUntil != nil && !p.DeferredUntil.After(now) {
		return fmt.Errorf(
			"a deferral returns on a date still to come: %s has passed",
			p.DeferredUntil.Format(time.DateOnly))
	}
	if p.CommittedTo != nil && !p.CommittedTo.After(now) {
		return fmt.Errorf(
			"promised work lands on a date still to come: %s has passed",
			p.CommittedTo.Format(time.DateOnly))
	}
	// A backport moves no version, which is the whole difference between the
	// two: naming one here would record an upgrade under the outcome
	// that exists for the case where there is not going to be one.
	if p.Outcome != UpgradeNeeded && strings.TrimSpace(p.UpgradeTo) != "" {
		return fmt.Errorf("%q moves no version", p.Outcome)
	}
	if p.Outcome == UpgradeNeeded && strings.TrimSpace(p.UpgradeTo) == "" {
		return errors.New("an upgrade needs the version it moves to")
	}
	return nil
}

// version is how a version string is read, everywhere it is read.
//
// Surrounding space is not part of a version. It has to be taken off in one
// place because the two halves disagreed otherwise: storing treated a
// whitespace-only version as absent, and matching treated it as a version
// that happened to be spaces — so a decision was written against nothing and
// looked for something, and could never apply to the place it was made about.
func version(s string) string { return strings.TrimSpace(s) }

// versionLimit is how long an upstream version a decision may be keyed on.
//
// The two version columns are part of the index every lookup of "does a
// decision apply to this finding" takes, and an index of that width has to
// stay inside what the narrowest supported server allows for one — which is
// where 191 comes from and why these are not the free-text columns the
// components they copy have.
//
// Measured against the reference producer's real output before settling for
// it: 6,845 components, longest version 49 characters, longest name 120,
// longest package identifier 140, and nothing at all over 191. The headroom is
// about fourfold on the field that matters.
const versionLimit = 191

// keyable refuses a place whose versions will not fit the key a decision is
// matched on.
//
// Refused here rather than left to the write, which would answer with a
// driver's message about a column nobody reading it has heard of. **Refused
// rather than truncated**, which is the important half: a decision keyed on a
// shortened version would be compared against the finding's full one and match
// nothing, so the claim would stand on the record, cover nothing, and say so
// nowhere.
func keyable(at Place) error {
	for what, held := range map[string]string{
		"component": at.ComponentUpstream,
		"consumer":  at.ConsumerUpstream,
	} {
		if len(version(held)) > versionLimit {
			return fmt.Errorf(
				"the %s's upstream version is %d characters and a decision is keyed on at most "+
					"%d, so this cannot be matched to a finding later — a version that long is "+
					"usually a producer putting something else in the field",
				what, len(version(held)), versionLimit)
		}
	}
	return nil
}

// text keeps an absent version absent rather than storing it as an empty one.
//
// The difference matters: a version nobody stated and a version that is the
// empty string would otherwise compare equal, and expiry is exactly a
// comparison of versions.
func text(s string) *string {
	trimmed := version(s)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// liveKeyFor is what a decision is a claim about: the place, and both upstream
// versions it was made against.
//
// Hashed rather than stored as its parts, because it exists to be compared for
// equality under a unique index and nothing ever reads it back. The versions
// are normalized the same way they are everywhere else, so a claim written with
// spaces around a version collides with one written without — which is the
// whole point of a uniqueness rule.
func liveKeyFor(at Place) string {
	basis := strings.Join([]string{
		strconv.FormatInt(at.ProductID, 10),
		strconv.FormatInt(at.VulnerabilityID, 10),
		at.PlaceIdentity,
		version(at.ComponentUpstream),
		version(at.ConsumerUpstream),
	}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// ErrAlreadyDecided is returned when a live claim already covers this exact
// combination of code.
//
// The answer is to revise that claim rather than to make a second one beside
// it: two claims about one finding are a disagreement, and a disagreement
// belongs in one place where both sides are readable.
var ErrAlreadyDecided = errors.New("a decision already stands here")

// alreadyDecided turns the constraint's refusal into a sentence naming which
// claim to go and read.
//
// Read after the transaction has unwound, which is why it is not part of the
// write: inside it the row that collided is the row this attempt could not
// see. Where the claim has since gone — withdrawn between the collision and
// the read — the original refusal stands, because a message naming a decision
// that is no longer there is worse than one naming none.
//
// Written four times, in three files, with the wording drifting by a word at
// each: the same refusal read "here" from one path and "at one of these
// places" from another for the same act on one place.
// placesOf is the places a set of proposals is about, for a refusal that has
// to name one of them.
func placesOf(proposals []Proposal) []Place {
	places := make([]Place, 0, len(proposals))
	for _, p := range proposals {
		places = append(places, p.Place)
	}
	return places
}

func (s *Store) alreadyDecided(ctx context.Context, err error, places []Place) error {
	if !errors.Is(err, ErrAlreadyDecided) {
		return err
	}
	where := "here"
	if len(places) > 1 {
		where = "at one of these places"
	}
	for _, place := range places {
		standing, found := s.liveAt(ctx, liveKeyFor(place))
		if !found {
			continue
		}
		return fmt.Errorf(
			"%w: decision %d is already %s %s — revise that one rather than recording a "+
				"second claim about the same code",
			ErrAlreadyDecided, standing.ID, standing.State, where)
	}
	return err
}

// ErrNothingOpen says a selection named nothing that is actually open where it
// was claimed to be.
//
// Its own error because it is not a refusal and not a fault in what was
// written: whatever was selected has since been fixed, closed or renamed, and
// what the caller should do about it is look again.
var ErrNothingOpen = errors.New("nothing named here is open")

// orEmpty reads a stored version back as the string a place states. The
// inverse of text, which is why neither is named for what it does to a value.
func orEmpty(stored *string) string {
	if stored == nil {
		return ""
	}
	return *stored
}

// visibilityOf reads a place's visibility, treating anything unset as not
// disclosed.
//
// Unset has to read as private, or a place assembled by something that forgot
// to state it would make a private finding argueable by anybody who can triage
// the public ones.
func visibilityOf(at Place) access.Visibility {
	if at.Visibility == access.Public {
		return access.Public
	}
	return access.Private
}

// Undecided keeps the places nothing currently stands at.
//
// For a decision reaching another build: the places its matching versions
// already cover by lookup are not to be claimed about again — that would be
// a second claim beside a standing one — and the rest are what is left to
// decide. Asked as one statement over the keys.
func (s *Store) Undecided(ctx context.Context, places []Place) ([]Place, error) {
	if len(places) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(places))
	for _, at := range places {
		keys = append(keys, liveKeyFor(at))
	}
	var standing []string
	if err := s.db.NewSelect().Model((*Decision)(nil)).
		ColumnExpr("de.live_key").
		Where("de.live_key IN (?)", bun.List(keys)).
		Scan(ctx, &standing); err != nil {
		return nil, fmt.Errorf("read what already stands: %w", err)
	}
	covered := make(map[string]bool, len(standing))
	for _, key := range standing {
		covered[key] = true
	}
	left := make([]Place, 0, len(places))
	for i, at := range places {
		if !covered[keys[i]] {
			left = append(left, at)
		}
	}
	return left, nil
}

// liveAt reads the claim currently standing over a combination of code, if
// there is one. Used to explain a refusal rather than to prevent one.
func (s *Store) liveAt(ctx context.Context, key string) (*Decision, bool) {
	standing := new(Decision)
	if err := s.db.NewSelect().Model(standing).
		Where("live_key = ?", key).Scan(ctx); err != nil {
		return nil, false
	}
	return standing, true
}

// reaching finds a decision a subject may act on, under a given rule.
//
// The rule differs by act: arguing about a finding needs the triage role,
// while agreeing to somebody else's claim is the approver capability alongside
// being able to read it. Reading what was decided follows whichever act
// produced it — anybody who could have taken part can see what came of it.
func (s *Store) reaching(ctx context.Context, subject access.Subject, decisionID int64,
	allowed func(access.Subject, int64, access.Visibility) bool, cases bool) (*Decision, error) {

	decision := new(Decision)
	// With its argument: everything that reads a decision back reads what it
	// said, and the row on its own carries only where it landed.
	if err := s.db.NewSelect().Model(decision).Relation("Claim").
		Where("de.id = ?", decisionID).Scan(ctx); err != nil {
		// A decision somebody may not reach and one that does not exist get
		// the same answer, so that guessing identifiers says nothing.
		return nil, ErrNotTheirs
	}
	if !allowed(subject, decision.ProductID, decision.Visibility) {
		// The case grant is the pair of a product and an issue, so it
		// can only be asked once the row is in hand — and it is asked
		// for reading alone. Arguing and agreeing keep the rule they
		// were given: a collaborator may argue about the issue they
		// were brought in on and may not agree to anybody's claim
		// about it.
		if !cases || !readableOn(subject, decision.ProductID,
			decision.VulnerabilityID, decision.Visibility) {
			return nil, ErrNotTheirs
		}
	}
	return decision, nil
}

// mayTakePart reports whether a subject may add to a decision rather than only
// read it — writing a comment, or changing their own.
//
// This is what readable meant before the record readable at the finding's
// visibility widened reading to the finding's own visibility. Writing had
// leaned on the reading rule, so widening one widened the other, and a reader
// could comment on a decision they may not argue about. Named separately so
// the two cannot drift back together.
func mayTakePart(subject access.Subject, productID int64, visibility access.Visibility) bool {
	return mayApprove(subject, productID, visibility) || mayDecide(subject, productID, visibility)
}

// readable reports whether a subject may see what was decided.
//
// It is the finding's own visibility and nothing else — the same question
// readableFindings asks a few lines below, which is the point: a decision is
// part of the record of a finding, and who may read that record is who may
// read the finding.
//
// It asked whether the subject may decide or approve, and that was narrower
// than disclosure opening the record, which says the whole record — comments,
// decisions, actors — goes public when a private issue is disclosed. Under the
// old rule that was true only for people who could already see it: a reader
// holding private reading on a product opened a finding and was told none of
// its decisions existed, so they saw "deferred" with no way to see why or by
// whom, and the screen called the record was empty for anybody who is not a
// triager.
//
// Acting on any of it is unchanged. Arguing still asks for triage (mayDecide)
// and agreeing still asks for the approver capability (mayApprove); this
// widens reading alone.
func readable(subject access.Subject, productID int64, visibility access.Visibility) bool {
	if subject.Kind != access.Person {
		return false
	}
	return subject.Reads(visibility, productID)
}

// readableOn is readable with the case grant asked beside the product-wide
// question.
//
// The list narrowing already asks it, so a collaborator's own case appeared
// among the decisions and every route that reads one of them by identifier
// refused it: listed and then not there, which reads as a fault rather than as
// a rule. The grant is the pair of a product and an issue, so it needs the
// issue, which a row carries and a bare product-and-visibility rule cannot
// see.
func readableOn(subject access.Subject, productID, vulnerabilityID int64,
	visibility access.Visibility) bool {

	if readable(subject, productID, visibility) {
		return true
	}
	for _, may := range access.VisibleOn(subject, productID, vulnerabilityID) {
		if may == visibility {
			return true
		}
	}
	return false
}

// approvableBy narrows a query to the decisions a subject may agree to, which
// is a wider set than the ones they may argue about.
func approvableBy(query *bun.SelectQuery, subject access.Subject, column string) *bun.SelectQuery {
	// Deliberately without the cases. A collaborator may argue about the
	// issue they were brought in on and may not agree to anybody's claim
	// about it : two of them could otherwise satisfy the two people a
	// dismissal on an embargoed finding asks for, with nobody accountable
	// for the product involved.
	return narrowedBy(query, subject, column, mayApprove, withoutCases)
}

// readableBy narrows a query to the decisions a subject may see.
func readableBy(query *bun.SelectQuery, subject access.Subject, column string) *bun.SelectQuery {
	return narrowedBy(query, subject, column, readable, onCases)
}

// narrowedBy applies one of those rules as a condition on the query.
//
// Written as a condition rather than as filtering afterwards, because a count,
// an export or a report is exactly where filtering afterwards gets forgotten —
// and where the number is the leak even when no row is shown.
//
// Public and private are kept apart because they permit different things:
// reaching undisclosed findings implies reaching disclosed ones, and the
// reverse is exactly what must not happen. The rule is asked separately for
// each, per product, so a new right cannot widen one by being written into the
// other.
//
// The products are bound as values. They come from the subject's own grants
// rather than from anything typed, so writing them into the statement would be
// safe today and would be the shape somebody copies later when the list does
// come from outside. Whether a narrowing also lets through the cases somebody
// was brought into . Named rather than a bare boolean at two call sites,
// because which of the two a narrowing is decides whether a collaborator can
// approve.
const (
	onCases      = true
	withoutCases = false
)

func narrowedBy(query *bun.SelectQuery, subject access.Subject, column string,
	allowed func(access.Subject, int64, access.Visibility) bool, cases bool) *bun.SelectQuery {

	if subject.Kind != access.Person {
		return query.Where("1 = 0")
	}
	products, all := subject.Products()
	if all {
		return query
	}

	var private, public []int64
	for _, id := range products {
		switch {
		case allowed(subject, id, access.Private):
			private = append(private, id)
		case allowed(subject, id, access.Public):
			public = append(public, id)
		}
	}
	brought := map[int64][]int64{}
	if cases {
		for _, id := range subject.CaseProducts() {
			// Only where the product's own grant is not already wider. A case
			// adds nothing where somebody reads the product undisclosed, and
			// the narrower clause would be dead weight on every read.
			if !subject.Reads(access.Private, id) {
				brought[id] = subject.Cases(id)
			}
		}
	}
	if len(private) == 0 && len(public) == 0 && len(brought) == 0 {
		return query.Where("1 = 0")
	}

	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		if len(private) > 0 {
			q = q.WhereOr(column+".product_id IN (?)", bun.List(private))
		}
		if len(public) > 0 {
			q = q.WhereOr(column+".product_id IN (?) AND "+column+".visibility = ?",
				bun.List(public), access.Public)
		}
		// One issue in one product, which is what a collaborator was brought
		// into. Read from the subject rather than from anything typed, so the
		// pairs are the ones resolved at sign-in.
		for _, productID := range sortedKeys(brought) {
			q = q.WhereOr(column+".product_id = ? AND "+column+".vulnerability_id IN (?)",
				productID, bun.List(brought[productID]))
		}
		return q
	})
}

// sortedKeys is the products of a case map in a settled order, so that two
// runs of the same query produce the same statement — which is what makes a
// prepared statement cache and a slow-query log worth reading.
func sortedKeys(cases map[int64][]int64) []int64 {
	out := make([]int64, 0, len(cases))
	for id := range cases {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// readableFindings narrows a query that joins findings to the ones a subject
// may read, per product: undisclosed findings where they read undisclosed
// findings on that product, disclosed ones everywhere else.
//
// The same rule as narrowedBy, asked of the finding's visibility and the
// product it sits in rather than the decision's. A decision somebody may read
// matches findings they may not, and a build name, a fix version or a count
// read off those is the disclosure — so every read that walks from a decision
// to its findings carries this.
//
// The finding's visibility is read through the given alias, and the product
// through the expression given — the stream's product where the read has
// joined that far, and the decision's where the match already requires the two
// to agree.
func readableFindings(query *bun.SelectQuery, subject access.Subject, finding, product string) *bun.SelectQuery {
	if subject.Kind != access.Person {
		return query.Where("1 = 0")
	}
	products, all := subject.Products()
	if all {
		return query
	}
	var private []int64
	for _, id := range products {
		if subject.Reads(access.Private, id) {
			private = append(private, id)
		}
	}
	if len(private) == 0 {
		return query.Where(finding+".visibility = ?", access.Public)
	}
	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.WhereOr(finding+".visibility = ?", access.Public).
			WhereOr(product+" IN (?)", bun.List(private))
	})
}

// DefaultTogetherCap is how many findings one action may claim about when
// nobody has set a limit.
//
// Generous, because the case this exists for is a kernel: a real image put
// 305,487 findings against one, and a person narrowing that down to the
// drivers their build does not include is doing the right thing with a long
// list. The bound is there because an unbounded write is something somebody
// triggers by accident, not because two thousand is a suspicious number.
const DefaultTogetherCap = 2000

// allowed is what every proposal has to satisfy before any of them is written.
//
// Checked over the whole set first, because refusing halfway is the failure
// these actions exist to avoid — and the bound is on the rows about to be
// written rather than on what a caller named, since one name expands into as
// many places as the issue sits at.
func allowed(subject access.Subject, proposals []Proposal, cap int, now time.Time) error {
	if cap <= 0 {
		cap = DefaultTogetherCap
	}
	if len(proposals) > cap {
		return fmt.Errorf("that is %d findings and the limit here is %d: narrow it, "+
			"or raise the limit deliberately", len(proposals), cap)
	}
	for _, p := range proposals {
		if !mayDecideOn(subject, p.Place.ProductID, p.Place.VulnerabilityID, visibilityOf(p.Place)) {
			return ErrNotTheirs
		}
		if err := p.valid(now); err != nil {
			return err
		}
		if p.By != subject.ID {
			return fmt.Errorf("a decision is recorded as made by whoever made it")
		}
	}
	return nil
}

// TogetherAt names what one judgment covers: some issues, and the build and
// component they sit at.
//
// The places themselves are not named. A caller free to name a place would be
// choosing which decisions apply where, and would be naming rows it read
// before this ran — so they are resolved here, inside the transaction that
// writes.
type TogetherAt struct {
	TargetID         int64
	ComponentID      int64
	VulnerabilityIDs []int64
}

// Together records the same judgment against many issues at one component.
//
// The transpose of grouping. One issue across many places is what a decision
// already covers; a component carrying thousands of issues — a kernel, most of
// them in drivers a given image never builds — has no answer at all, and
// without one the choices are answering two thousand findings individually,
// which nobody does, or hiding them, which is refused.
//
// One outcome, one justification, one reasoning, one approval, and a separate
// record per issue **and per place**. Each is keyed and expires on its own,
// which is what makes one action across many findings defensible rather than a
// blanket claim — and covering every place is what stops it reporting that it
// answered a consumer it left open.
//
// Everything authorization turns on is read inside the transaction that writes
// . Which product these sit in, and whether any of them is undisclosed, decide
// whether this person may make the claim at all; read before the transaction,
// they would be answers about a database that has since moved.
//
// Bounded, because one action writing an unbounded number of rows is a denial
// of service somebody triggers by accident. The bound is checked against the
// places this actually resolves to — the count somebody is asked to narrow is
// the number of rows about to be written, not the number of names they typed.
func (s *Store) Together(ctx context.Context, subject access.Subject, at TogetherAt, p Proposal,
	cap int) (claimID int64, recorded []int64, err error) {

	if len(at.VulnerabilityIDs) == 0 {
		return 0, nil, fmt.Errorf("nothing was selected, so there is nothing to claim")
	}
	if p.By != subject.ID {
		return 0, nil, fmt.Errorf("a decision is recorded as made by whoever made it")
	}

	db, ok := s.db.(*bun.DB)
	if !ok {
		return 0, nil, fmt.Errorf("this store is already inside a transaction")
	}

	err = database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		// Cleared on every attempt. A retry re-runs this against a database
		// that has moved, and carrying identifiers over from the attempt that
		// failed would report claims that no longer exist.
		recorded = recorded[:0]
		claimID = 0
		within := &Store{db: tx, now: s.now}

		places, err := placesWithin(ctx, tx, subject, at)
		if err != nil {
			return err
		}
		if len(places) == 0 {
			return fmt.Errorf("%w against that component", ErrNothingOpen)
		}
		if cap > 0 && len(places) > cap {
			return fmt.Errorf("that is %d findings and the limit here is %d: narrow the "+
				"selection, or raise the limit deliberately", len(places), cap)
		}

		claim, err := within.newClaim(ctx, TogetherClaim, subject.ID, nil, p.SelectedBy, p)
		if err != nil {
			return err
		}
		claimID = claim.ID
		each := make([]Proposal, 0, len(places))
		for _, place := range places {
			if !mayDecide(subject, place.ProductID, visibilityOf(place.Place)) {
				return ErrNotTheirs
			}
			one := p
			one.Place = place.Place
			one.SeverityCenti = place.SeverityCenti
			if err := one.valid(s.now()); err != nil {
				return err
			}
			each = append(each, one)
		}
		made, err := within.proposeAll(ctx, claim, each)
		if err != nil {
			// One live claim per combination of code holds here too. A
			// selection covering something already decided is a selection
			// somebody should look at again rather than one to write around.
			if errors.Is(err, ErrAlreadyDecided) {
				return fmt.Errorf("%w: something in this selection is already decided",
					ErrAlreadyDecided)
			}
			return err
		}
		for _, one := range made {
			recorded = append(recorded, one.ID)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return claimID, recorded, nil
}

// onlyDecidable narrows a places query to what this subject may argue about.
//
// Written here rather than through narrowedBy because the product and the
// visibility sit on different tables in this statement — the product on the
// stream, the visibility on the finding — and narrowedBy takes one alias for
// both.
func onlyDecidable(query *bun.SelectQuery, subject access.Subject) *bun.SelectQuery {
	if subject.Kind != access.Person {
		return query.Where("1 = 0")
	}
	products, all := subject.Products()
	if all {
		return query
	}
	var private, public []int64
	for _, id := range products {
		switch {
		case mayDecide(subject, id, access.Private):
			private = append(private, id)
		case mayDecide(subject, id, access.Public):
			public = append(public, id)
		}
	}
	if len(private) == 0 && len(public) == 0 {
		return query.Where("1 = 0")
	}
	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		if len(private) > 0 {
			q = q.WhereOr("st.product_id IN (?)", bun.List(private))
		}
		if len(public) > 0 {
			q = q.WhereOr("st.product_id IN (?) AND f.visibility = ?",
				bun.List(public), access.Public)
		}
		return q
	})
}

// resolved is a place a judgment is about to be written against, with how bad
// the issue there is judged to be.
type resolved struct {
	Place
	SeverityCenti int
}

// placesWithin reads every open place the named issues occupy at one
// component, in the transaction that is about to write against them.
//
// Narrowed to what this subject may read, like every other query here. A claim
// therefore covers every place the person making it can see, and the places
// they cannot are left open for whoever can — which is the ordinary division
// of work rather than a gap. The alternative, refusing the whole action
// because something undisclosed sits at the same component, answers a person
// who picked from the list they were shown with a bare "not found" and no way
// to tell why.
func placesWithin(ctx context.Context, tx bun.Tx, subject access.Subject,
	at TogetherAt) ([]resolved, error) {

	var rows []struct {
		ProductID         int64  `bun:"product_id"`
		VulnerabilityID   int64  `bun:"vulnerability_id"`
		PlaceIdentity     string `bun:"place_identity"`
		Visibility        string `bun:"visibility"`
		ComponentUpstream string `bun:"component_upstream"`
		ConsumerUpstream  string `bun:"consumer_upstream"`
		Severity          int    `bun:"severity_centi"`
		OnTag             int    `bun:"on_tag"`
	}
	query := tx.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("LEFT JOIN component AS uc ON uc.id = f.consumer_id").
		ColumnExpr("st.product_id AS product_id").
		ColumnExpr("f.vulnerability_id AS vulnerability_id").
		ColumnExpr("f.place_identity AS place_identity").
		ColumnExpr("f.visibility AS visibility").
		ColumnExpr(finding.ComponentUpstreamExpr+" AS component_upstream").
		ColumnExpr(finding.ConsumerUpstreamExpr+" AS consumer_upstream").
		ColumnExpr("COALESCE(v.score_centi, 0) AS severity_centi").
		// Whether the release was built once, which decides what may be said
		// about it. As an integer rather than a boolean: the four engines
		// spell a boolean three ways.
		ColumnExpr("MAX(CASE WHEN st.kind = ? THEN 1 ELSE 0 END) AS on_tag", catalog.Tag).
		Where("f.target_id = ?", at.TargetID).
		Where("f.component_id = ?", at.ComponentID).
		Where("f.closed_at IS NULL").
		Where("f.vulnerability_id IN (?)", bun.List(at.VulnerabilityIDs)).
		GroupExpr("st.product_id, f.vulnerability_id, f.place_identity, f.visibility, " +
			"c.upstream_version, c.version, uc.upstream_version, uc.version, v.score_centi").
		OrderExpr("f.vulnerability_id, f.place_identity")
	if err := onlyDecidable(query, subject).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read where these issues sit: %w", err)
	}

	places := make([]resolved, 0, len(rows))
	for _, row := range rows {
		places = append(places, resolved{
			Place: Place{
				ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
				PlaceIdentity:     row.PlaceIdentity,
				Visibility:        access.AsVisibility(row.Visibility),
				ComponentUpstream: row.ComponentUpstream,
				ConsumerUpstream:  row.ConsumerUpstream,
				OnTag:             row.OnTag == 1,
			},
			SeverityCenti: row.Severity,
		})
	}
	return places, nil
}
