// Package setting holds what an administrator changes from inside the
// application, as opposed to what an operator sets when deploying it.
//
// The split matters: a configuration file is edited by whoever can reach the
// filesystem and restart the process, and an administrator is generally not
// that person. Anything an administrator is expected to tune belongs here so
// that tuning it is an action in the application with a record of who did it,
// rather than a deployment.
package setting

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Setting is one named value.
type Setting struct {
	// Aliased "st", not "as": all four engines reserve the second, and it
	// worked only because the library quotes what a tag declares — a property
	// of the library rather than of this code. The first raw expression
	// naming the alias would have been a syntax error on every one of them,
	// and the gate that checks invented names read call arguments rather than
	// struct tags, so nothing could have said so.
	bun.BaseModel `bun:"table:application_setting,alias:st"`

	Name      string    `bun:"name,pk"`
	Value     string    `bun:"value,notnull"`
	UpdatedAt time.Time `bun:"updated_at,notnull"`
}

// The names in use. They are spelled once here rather than at each call site,
// because a misspelling would read as a setting nobody has changed yet and so
// silently take the default.
const (
	// SessionLifetime bounds how long a sign-in lasts. It is also the window
	// in which somebody who moved out of a team still holds what the team gave
	// them, because group membership is only read at sign-in.
	SessionLifetime = "session.lifetime"
	// RoleMode is where roles come from: assigned by an administrator, or
	// derived from provider groups. One mode for the whole deployment.
	RoleMode = "roles.mode"
	// MaxTokenLifetime is the longest a person's own credential may last.
	// Expiry is mandatory; this is how far out it may be set.
	MaxTokenLifetime = "token.max-lifetime"
	// ClaimWindow is how long an authorization an administrator wrote stays
	// redeemable before the person it names has ever signed in.
	//
	// An unredeemed authorization is matched by name alone, because the
	// identifier it will be pinned to is not knowable until somebody arrives
	// holding it. That is the one window in which a name decides who gets
	// somebody else's roles, so it has an end: a grant written for somebody
	// who never came is withdrawn rather than left standing for ever.
	ClaimWindow = "signin.claim-window"
	// DiscloseAfter is how long a finding nobody has announced stays that way
	// before the date arrives. It gives the embargo an end somebody outside
	// could hold us to, which is the point of having one at all.
	DiscloseAfter = "disclosure.after"
	// MovementThreshold is how far an embargo's end may be carried, in total,
	// before a second person has to agree to moving it further. Cumulative for
	// the same reason the deferral one is: measured per movement, the
	// exception swallows the rule three weeks at a time. Both acts count, and
	// each by how far it moved the date rather than by which way.
	MovementThreshold = "disclosure.movement-threshold"
	// DeferralThreshold is how long something may be put off before a second
	// person has to agree. It ships with a starting point rather than a fixed
	// rule, because how long is too long is a judgment about a product.
	DeferralThreshold = "triage.deferral-threshold"
	// SignInKey is the deployment's own key for signing what a sign-in
	// leaves in the browser while it is away at a provider.
	//
	// Not an offered setting and not in the settable list: an operator
	// never types it and nothing reads it back out. It lives here because
	// it has to be the same across replicas and survive a restart, and this
	// is where deployment state already is. Minted on first use.
	SignInKey = "signin.key"
	// TriageFloor is what this deployment considers worth triaging: a
	// severity word, below which a finding is recorded and counted but
	// kept out of the working list. A product may state its own instead.
	TriageFloor = "triage.floor"

	// DisclosureLead is how long before an embargo's date somebody is told
	// it is coming. The date arriving is the last moment to act rather
	// than the first useful warning, and an extension approval is
	// worthless without time to grant it.
	DisclosureLead = "disclosure.lead-time"

	// The Due values are how long a finding may stay open before it is late,
	// by how urgent it is.
	//
	// Being exploited has its own, and it is the shortest: severity is how
	// bad the flaw is, and being exploited is a fact about the world.
	// Without a separate one the deadline contradicts the ranking, which
	// puts an exploited medium above an unexploited critical — the list
	// would say look at this first while the clock said ninety days.
	DueExploited = "remediation.due.exploited"
	DueCritical  = "remediation.due.critical"
	DueHigh      = "remediation.due.high"
	DueMedium    = "remediation.due.medium"
	DueLow       = "remediation.due.low"
	// TogetherCap is how many findings one bulk judgment may cover at
	// once, and how many reports one ruling may cover. A bound rather than none, because a single action writing an
	// unbounded number of rows is a denial of service somebody triggers by
	// accident. How generous it should be is a judgment about a product — a
	// kernel's list is long — so it is tuned here rather than compiled in.
	//
	// A promise to upgrade is not bounded by this, and by nothing else
	// either. The distinction is reversibility rather than size: nothing
	// re-checks a dismissal, so one sentence answering a thousand findings has
	// to stay a size a reviewer can follow, while the next scan re-checks
	// every row a promise names.
	TogetherCap = "triage.together-cap"
	// QuietAfter is how long a declared build may go without a scan arriving
	// before it is reported as having gone quiet.
	//
	// It is a judgment about how often a deployment expects to be scanned —
	// nightly for some, on a release cadence for others — so it is tuned here
	// rather than compiled in. A build that stops being scanned reports no new
	// findings and fails nothing, which is why silence has to be looked for
	// rather than waited for.
	QuietAfter = "scanning.quiet-after"
	// VulnerabilityDataStaleAfter is how long the vulnerability data may go
	// without moving before the deployment is told.
	//
	// A scan whose data has not moved in a month answers the same way it did a
	// month ago, and it answers with the same confidence — which is the whole
	// danger. Nothing fails, no scan is refused, and every finding on every
	// screen is as old as the data behind it without saying so.
	//
	// The length is a judgment about how a deployment gets its data: one that
	// downloads nightly expects it to move most days, and one that carries a
	// bundle across an air gap on a schedule expects otherwise. So it is tuned
	// here rather than compiled in.
	VulnerabilityDataStaleAfter = "scanning.data-stale-after"
	// DeltaShare and DeltaFloor are when an upload has changed enough of a
	// build's inventory that somebody is told.
	//
	// Two rather than one, and both have to be passed. A share alone fires on
	// an inventory of ten every time three names move, which is an ordinary
	// night. A count alone is either that same noise or, set high enough to
	// stop it, silence on the build that replaced every dependency it had.
	// The share is what makes the question "is this unlike this build" and
	// the floor is what keeps a small inventory from asking it.
	//
	// Both are a judgment about a deployment: how much a build moves between
	// nights depends on what it is built from, and a base image that rolls
	// weekly is not a fault.
	DeltaShare = "scanning.delta-share"
	DeltaFloor = "scanning.delta-floor"
	// PairShare and PairApprovers are when the same two people agreeing to
	// each other's work is raised with administrators.
	//
	// Two rather than one, and both have to be met. A share alone is
	// permanently true in a team of two, where one pair is every agreement
	// there is. The count of people who may approve is what says the team is
	// large enough that one pair doing everything is a choice rather than the
	// shape of the team. A product may state its own of either, because teams
	// differ in size product to product.
	PairShare     = "triage.pair-share"
	PairApprovers = "triage.pair-approvers"
	// ScanEvery is how often everything tracked is scanned again against
	// the vulnerability data of the day.
	//
	// A judgment about a deployment rather than a constant: the data moves
	// daily, so scanning more often than that measures the same thing
	// twice, and scanning much less often means an advisory published this
	// morning waits to be noticed. It is tuned here rather than compiled
	// in because what a deployment's scanner costs to run over its whole
	// estate is a question about that estate.
	//
	// It is also how often each configured supplier is read again, because
	// that is the same question: what is known about what a build ships moves
	// on the cadence the vulnerability data does. Shortening it multiplies
	// requests to third parties as well as scans here.
	ScanEvery = "scanning.every"
	// SupplierSilentAfter is how long a configured supplier may go without a
	// successful read before administrators are told.
	//
	// A supplier that stopped answering looks exactly like one that has
	// published nothing, which is the silent failure the system screen exists
	// for. The length is a judgment about how patient to be with somebody
	// else's service, so it is tuned here rather than compiled in.
	SupplierSilentAfter = "scanning.supplier-silent-after"
	// UpstreamCurrency is whether this deployment asks public package
	// indexes what the newest version of a component is.
	//
	// Off unless somebody turns it on, and the only setting here that sends
	// anything to a service nobody configured. Everything a scan needs
	// arrives as a file somebody imported
	// deliberately, so that a scan answers the same way twice and nothing a
	// scan depends on is somebody else's server being up (REQ-12). This
	// stands outside that: it is not part of a scan, and it is asked of a
	// public index. A deployment that cannot reach out loses this answer and
	// whatever a configured supplier would have said; what a scan reports is
	// unaffected.
	//
	// A component's name goes out. One request per component to
	// that ecosystem's public index, carrying the name and nothing else — no
	// version, no build, no product, nothing about who is asking beyond the
	// request itself. For an open-source dependency that is public knowledge.
	// For something built here it is the name of a project, a team or a
	// product nobody has announced, and a public index records every request
	// made of it, so names this deployment calls its own are held back and the
	// report says which.
	UpstreamCurrency = "upstream.currency"
	// AttachmentMaxSize is the largest single file this deployment
	// accepts, in bytes, and AttachmentQuota is how much it will hold in
	// total.
	//
	// Two limits rather than one because they answer different questions.
	// The first stops one upload being enormous; the second stops many
	// ordinary ones filling a disk somebody else pays for. Storage that
	// another person fills on our behalf needs a ceiling, and how high it
	// should be is a judgment about a deployment rather than a constant.
	AttachmentMaxSize = "attachment.max-size"
	AttachmentQuota   = "attachment.quota"
	// QueueBacklog is how much work of one kind may be waiting before more of
	// that kind is refused.
	//
	// Per kind, so a producer that has filled its own queue does not refuse
	// everybody else's work. Settable because what a deployment can hold is a
	// question about that deployment: an estate large enough to push more than
	// the shipped number of scans in faster than the workers drain them has no
	// remedy for a compiled-in one short of a new binary, and the producer
	// that is refused is a build.
	QueueBacklog = "queue.backlog"
	// RoutingBatch is how many findings one pass of the routing sweep may
	// place. A bulk judgment is bounded, and the bound is a setting: an
	// operator on a large estate has a reason to move it either way, and
	// rebuilding is not a way to change a number.
	RoutingBatch = "routing.batch"
	// SavedPerPerson is how many filters one person may keep for one
	// product.
	//
	// A ceiling on rows one person writes one at a time, which is the
	// neighboring case to a bulk judgment and is bounded for the same reason:
	// nothing else stopped a script, or a keyboard shortcut held down, from
	// filling the table — and the panel that lists them reads every row it
	// finds on every open. Settable because how many narrowings a person
	// genuinely keeps is a judgment about how they work.
	SavedPerPerson = "saved.max-per-person"
	// AttachmentShare is how much of that one person may hold, in bytes.
	//
	// The deployment-wide quota bounds the store and nothing bounded any
	// one uploader's part of it, so filling it was one person's to do and
	// what it cost everybody else was every upload afterwards, in every
	// product.
	AttachmentShare = "attachment.per-person-quota"
	// The four periods after which work that has not moved is a condition
	// somebody is told about.
	//
	// Settings rather than constants for the reason every other threshold
	// here is one: what counts as stale is a judgment about a deployment.
	// A team approving twice a week and a team approving twice a day
	// disagree about when a claim has been waiting too long, and neither
	// is wrong.
	//
	// Four rather than one, because they are four different waits. A claim
	// waiting on a second person is somebody else's turn and the ordinary
	// case is days; a claim sent back is the proposer's own turn and
	// should be shorter, because they were asked a question; a deferral
	// ending needs enough warning to do the work again before it lapses;
	// and a team queue is nobody's turn at all, which is why it is the one
	// that hides.
	WaitingAfter = "triage.waiting-after"
	// SentBackAfter is how long a claim an approver asked more of may sit
	// untouched before its proposer is told again.
	SentBackAfter = "triage.sent-back-after"
	// DeferralLead is how long before a deferral's end date its proposer hears
	// that it is coming. The date arriving puts the finding back in the queue,
	// which is the last moment rather than the first useful warning — the same
	// shape as an embargo's lead time.
	DeferralLead = "triage.deferral-lead"
	// QueuedAfter is how long work may sit in a team's queue with nobody
	// having taken it.
	QueuedAfter = "triage.queued-after"

	// AbsentAfter is how long somebody may go without signing in before
	// work they are holding is worth an administrator's attention.
	//
	// A judgment about a team rather than a constant: two weeks is a
	// holiday in one place and a resignation in another. It only ever asks
	// — long leave and having left look identical from here, and nothing
	// detects somebody leaving.
	AbsentAfter = "people.absent-after"
)

// DefaultAbsentAfter is how long counts as absent where nobody has said.
//
// Two weeks: long enough that an ordinary holiday does not raise it, short
// enough that work stuck behind somebody who has gone is noticed in the month
// it happens rather than the quarter.
const DefaultAbsentAfter = 14 * 24 * time.Hour

// The four staleness periods where nobody has said.
//
// A working week for a claim waiting on somebody else, which is long enough
// that an approver who reviews on Fridays is not told about Monday's work on
// Tuesday. Three days for one sent back, because the question was asked of the
// person who is already holding it. A week of warning before a deferral ends,
// so that the work it was put off for can be done rather than discovered to be
// late. Three days for a team's queue, which is the one that looks handled and
// is not.
const (
	DefaultWaitingAfter  = 5 * 24 * time.Hour
	DefaultSentBackAfter = 3 * 24 * time.Hour
	DefaultDeferralLead  = 7 * 24 * time.Hour
	// DefaultDisclosureLead is how long before an embargo's date the
	// people who could still move it are told it is coming. Longer than a
	// deferral's warning, because agreeing to an extension needs a second
	// person and an approver touches disclosure a few times a year.
	DefaultDisclosureLead = 14 * 24 * time.Hour
	DefaultQueuedAfter    = 3 * 24 * time.Hour
)

// DefaultRoutingBatch is how many findings one routing pass places where
// nobody has said.
//
// Generous, because the case it exists for is an estate where a rule matches
// tens of thousands of rows at once; the bound is there because an unbounded
// write is something somebody triggers by accident, not because two thousand
// is a suspicious number.
const DefaultRoutingBatch = 2000

// DefaultSavedPerPerson is how many filters one person may keep for one
// product where nobody has said.
//
// A hundred: past anything somebody curates by hand, and low enough that a
// list of them is still a list. The bound is there because an unbounded number
// of rows one person can write is a table nobody meant to fill, not because a
// hundred is a suspicious number.
const DefaultSavedPerPerson = 100

// DefaultTogetherCap is how many rows one bulk judgment may write where nobody
// has said.
//
// Generous, because the case this exists for is a kernel: a real image put
// 305,487 findings against one, and a person narrowing that down to the
// drivers their build does not include is doing the right thing with a long
// list. The bound is there because an unbounded write is something somebody
// triggers by accident, not because two thousand is a suspicious number.
//
// Here rather than in the package that first needed it, because the packages
// that read it cannot all see each other: recording a flaw bounds what it
// opens, and a finding cannot import a triage decision.
const DefaultTogetherCap = 2000

// DefaultQueueBacklog is how much work of one kind may wait where nobody has
// said.
//
// A thousand: deep enough that an ordinary night of builds never reaches it,
// shallow enough that a producer which has genuinely run away is refused
// before the table is the problem.
const DefaultQueueBacklog = 1000

// DefaultAttachmentMaxSize is what one file may be where nobody has said.
//
// Screenshots and logs are what people attach, and both fit comfortably. It is
// deliberately not generous: an operator who wants to accept a core dump can
// say so, and the direction that needs a deliberate act is the one that fills
// a disk.
const DefaultAttachmentMaxSize = 25 << 20

// DefaultAttachmentQuota is what a deployment holds in total where nobody has
// said. Four hundred files at the default size, which is a working year for a
// team and small enough that filling it is noticed rather than invoiced.
const DefaultAttachmentQuota = 10 << 30

// DefaultAttachmentShare is how much of that one person holds where nobody has
// said.
//
// An eighth of the shipped total: a starting point rather than a
// recommendation, like every other shipped number here. What it is for is that
// one account cannot take the whole store, and a deployment where somebody
// legitimately needs more says so.
const DefaultAttachmentShare = 1 << 30

// DefaultQuietAfter is how long a build may go unscanned before it is reported
// as having gone quiet, where a deployment has not said otherwise.
//
// A week: long enough that a nightly build missing one night is not an alert,
// short enough that a pipeline switched off is noticed in the week it happened.
//
// It lives beside the name it defaults rather than in whichever package needed
// it first, because two now do — the endpoint that answers what has been
// scanned, and the pass that turns going quiet into something somebody is
// told. Two copies of a default is two policies that agree until one moves.
const DefaultQuietAfter = 7 * 24 * time.Hour

// DefaultVulnerabilityDataStaleAfter is how long the vulnerability data may go
// without moving before the deployment is told, where it has not said
// otherwise.
//
// A week, for the reason the quiet-build window is a week: long enough that a
// publisher having a slow few days is not an alert, short enough that a feed
// that stopped being fetched is noticed in the week it stopped.
const DefaultVulnerabilityDataStaleAfter = 7 * 24 * time.Hour

// DefaultPairShare is the share of a product's agreements, as a percentage,
// at which one pair agreeing to each other's work is raised with
// administrators, where nobody has said.
//
// Four in five: past what an ordinary rota produces in a team of three or
// more, and short of the whole, so a pair covering nearly everything is caught
// before it covers all of it.
const DefaultPairShare = 80

// DefaultPairApprovers is the fewest people who may approve in a product for
// one pair's share to be worth raising, where nobody has said.
//
// Three: the smallest team in which one pair doing everything is not simply
// what the team is.
const DefaultPairApprovers = 3

// DefaultDeltaShare is how much of a build's inventory may move in one upload
// before the deployment is told, as a percentage, where nobody has said.
//
// A quarter: past what a night of dependency upgrades moves, and short of the
// half an inventory loses when a document arrives describing part of a build.
// Like every other shipped number here it is a starting point rather than a
// recommendation.
const DefaultDeltaShare = 25

// DefaultDeltaFloor is the fewest names that counts as a move worth telling
// anybody about, where nobody has said.
//
// Ten, so that a build of a dozen dependencies is not reported for the three
// that moved. What it costs is that a very small inventory has to be replaced
// outright to be reported at all, which is the direction to be wrong in: an
// alert nobody believes is one nobody reads.
const DefaultDeltaFloor = 10

// DefaultScanEvery is how often everything tracked is scanned again, where a
// deployment has not said otherwise.
//
// A day, because the vulnerability databases the scanner reads are published
// daily: more often measures the same data twice, and less often means an
// advisory published this morning waits for the difference before anybody sees
// it against a release that has not been rebuilt in a year.
const DefaultScanEvery = 24 * time.Hour

// DefaultSupplierSilentAfter is how long a supplier may go unread before the
// deployment is told, where nobody has said.
//
// A week, for the reason the quiet-build window is a week: a publisher having a
// bad day is not an alert, and one that stopped answering is noticed in the
// week it stopped.
const DefaultSupplierSilentAfter = 7 * 24 * time.Hour

// DefaultDiscloseAfter is how long an undisclosed finding has before its date
// arrives, where a deployment has not said otherwise.
//
// Ninety days is what coordinated disclosure practice converges on, and the
// number matters less than there being one: an embargo with no end is the
// indefinite secrecy the disclosure frameworks warn about, arrived at by
// nobody deciding anything.
//
// Reaching the date discloses nothing on its own. It is a date to answer, not
// a trigger.
const DefaultDiscloseAfter = 90 * 24 * time.Hour

// DefaultMovementThreshold is how far an embargo's end may be carried in total
// before a second person has to agree.
//
// Thirty days: enough that a fix slipping a sprint is ordinary triage, and not
// enough that a ninety-day embargo becomes a year without anybody else
// noticing. Like the deferral threshold it ships as a starting point rather
// than a rule, because how long is too long is a judgment about a product.
const DefaultMovementThreshold = 30 * 24 * time.Hour

// On and Off are what a setting that is a switch may be set to.
//
// Words rather than true/false, because every setting is stored and returned
// as text and "on" reads the same in the store, in the API and on the screen.
const (
	On  = "on"
	Off = "off"
)

// Store reads and writes settings.
type Store struct {
	db  bun.IDB
	now func() time.Time
	// beforeInsert runs after the opening read and before the insert that may
	// collide with another writer. Nil everywhere but the test that pins what
	// happens when it does.
	//
	// A seam rather than a hope: without one the four writers race only if the
	// scheduler happens to interleave them, so a run where nothing collided is
	// indistinguishable from a run where the recovery worked — which is how a
	// recovery broken on every server engine passed locally and failed in CI.
	beforeInsert func()
	// beforeWrite is the same seam for Change, between the read that answers
	// what the setting held and the write that replaces it. Two writers held
	// here have both read the original, which is the interleave that made both
	// of them report replacing it.
	beforeWrite func()
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Get reads a setting, returning whether it has been set at all.
//
// Unset is not an error. Every setting has a default, and a deployment that
// has never been tuned is the ordinary case rather than a fault.
//
// A failure to read is not "unset", though, and treating the two as one
// was worse than it looks. Every caller falls back to a default when a setting
// is unset, so a database that could not answer would silently swap the
// deployment's configuration for the shipped one — including the threshold
// deciding which deferrals need a second person. A policy that quietly becomes
// a different policy under load is the kind of failure nobody finds, because
// nothing anywhere reports it.
func (s *Store) Get(ctx context.Context, name string) (string, bool, error) {
	row := new(Setting)
	switch err := s.db.NewSelect().Model(row).Where("name = ?", name).Scan(ctx); {
	case database.IsNoRows(err):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("read the %q setting: %w", name, err)
	}
	return row.Value, true, nil
}

// Set records a setting, whether or not anybody has set it before.
//
// Written as a read and then one of two writes rather than as one upsert
// statement, because there is no portable spelling of an upsert: two of the
// four engines want ON CONFLICT and the other two want ON DUPLICATE KEY UPDATE,
// and engine-specific SQL is confined to migration data-definition and the
// queue's locking.
//
// The read decides which write, and both writes say so if the read was already
// out of date. A setting somebody has changed before is updated on the name and
// on the value that was read, so a writer whose row has moved matches nothing
// and goes again. A never-before-set one is inserted, and two administrators
// setting it at once resolve against the primary key: one wins and the loser
// goes round again, landing in the update arm. Either retry is a fresh
// transaction for the reason SetIfAbsent's is — a read inside the transaction
// whose insert failed sees nothing on two engines and is refused outright on a
// third, and one inside a transaction whose snapshot is fixed answers with the
// same stale value for ever.
func (s *Store) Set(ctx context.Context, name, value string) error {
	_, _, err := s.Change(ctx, name, value)
	return err
}

// errMoved says the row changed between the read that answered what the
// setting held and the write meant to replace it.
//
// The attempt goes out whole rather than reading again inside it, for the
// reason SetIfAbsent's retry does: MySQL and MariaDB fixed the transaction's
// snapshot at the opening select, so a second read there answers with the same
// stale value however many times it is asked.
var errMoved = errors.New("the setting moved between the read and the write")

// Change records a setting and answers what it replaced.
//
// The value it replaced comes from the same transaction as the write, and the
// write carries it: the update matches on the name *and* on the value the read
// answered with. Both halves are needed. Read in a statement of its own, before
// is what the setting held at some earlier moment; read inside the transaction
// but not written into the condition, it is what the setting held when the read
// ran, which is not the same thing either.
//
// At the isolation every engine opens with, a plain read takes no lock. Two
// administrators moving the same setting at once both read the original; the
// second's update waits on the first's row lock, and then lands on top of the
// value it never saw. Both report replacing the original, and what each reports
// is written into an append-only trail — so the setting ends up right and the
// record of who changed what is wrong about the what. The condition is what
// makes the loser's write match nothing, so that it goes again and reports what
// it actually replaced.
//
// A condition rather than a locking read, because SELECT ... FOR UPDATE is
// spelled per engine and this works the same on all four.
//
// had distinguishes "it held nothing" from "it held the empty string", which
// is the difference between a deployment that never tuned this and one that
// cleared it.
func (s *Store) Change(ctx context.Context, name, value string) (string, bool, error) {
	// Inside somebody else's transaction — an administrator moving a setting,
	// recorded in the same transaction as the act — the race is theirs to take
	// again. Going again here would re-run against a transaction the failed
	// statement has already poisoned, and would leave the other half of the
	// act standing on a read that has moved.
	if _, own := database.Handle(s.db); !own {
		before, had, err := s.change(ctx, name, value)
		if database.IsDuplicate(err) || errors.Is(err, errMoved) {
			return "", false, fmt.Errorf("record the %q setting: %w", name, database.ErrGoAgain)
		}
		return before, had, err
	}

	// Bounded, rather than the "once more and no further" a collision on the
	// primary key uses: the loser of that one lands in the update arm and is
	// done, while a writer whose condition matched nothing can lose the row
	// again to a third administrator moving the same setting. Bounded rather
	// than looped, because contention nothing resolves has to be reported.
	var err error
	for attempt := 1; attempt <= database.Attempts; attempt++ {
		var before string
		var had bool
		before, had, err = s.change(ctx, name, value)
		if database.IsDuplicate(err) || errors.Is(err, errMoved) {
			continue
		}
		return before, had, err
	}
	return "", false, fmt.Errorf("record the %q setting: gave up after %d attempts: %w",
		name, database.Attempts, err)
}

// change is one attempt, letting a duplicate out for the caller to take again.
func (s *Store) change(ctx context.Context, name, value string) (before string, had bool, err error) {
	// Inside one transaction, and retried whole. Written as two statements it
	// could report success having stored nothing: the update matches no row,
	// another writer inserts one, and a separate existence check then sees a
	// row that the caller's value never reached. Whether the row exists and
	// what it says have to be decided in the same view.
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		// Every attempt starts from nothing: a rolled-back attempt read a row
		// that no longer describes anything.
		before, had = "", false
		now := s.now().Truncate(time.Microsecond)

		// The stored value, in the same view as the write that replaces it.
		held := new(Setting)
		switch err := tx.NewSelect().Model(held).Where("name = ?", name).Scan(ctx); {
		case database.IsNoRows(err):
		case err != nil:
			return fmt.Errorf("read the %q setting: %w", name, err)
		default:
			before, had = held.Value, true
		}

		if s.beforeWrite != nil {
			s.beforeWrite()
		}

		// Nothing held it, so there is nothing to replace and the primary key
		// decides who was first. An update here would take a row another
		// writer committed since the read and report having replaced nothing
		// while replacing what that writer stored.
		if !had {
			row := &Setting{Name: name, Value: value, UpdatedAt: now}
			if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
				// Out whole, so the caller opens a new transaction whose read
				// can see the row the winner committed. Left to fall through,
				// one of two administrators setting a never-before-set value
				// at once was handed a raw constraint violation.
				if database.IsDuplicate(err) {
					return err
				}
				return fmt.Errorf("record the %q setting: %w", name, err)
			}
			return nil
		}

		res, err := tx.NewUpdate().Model((*Setting)(nil)).
			Set("value = ?", value).Set("updated_at = ?", now).
			Where("name = ?", name).Where("value = ?", before).Exec(ctx)
		if err != nil {
			return fmt.Errorf("record the %q setting: %w", name, err)
		}

		// The rows the update matched, which is the question being asked
		// — whether the row still holds what the read answered with. This
		// counted the rows in a second statement instead, on the ground that
		// two of the four engines report nothing touched when an update writes
		// a value identical to the one already stored. The connection settings
		// make that untrue: the count is rows matched on all four, so a match
		// of none is the row having moved rather than the value already being
		// the one being written.
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("record the %q setting: %w", name, err)
		}
		if n == 0 {
			return errMoved
		}
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return before, had, nil
}

// SetIfAbsent records a setting only where nothing holds it yet, and answers
// what is stored afterwards — whatever that turns out to be.
//
// For the values a deployment mints for itself rather than an operator types:
// a signing key is one of those, and two replicas starting together both find
// nothing and both mint. Written as a plain Set, the second overwrites the
// first, and every session signed with the key that lost stops verifying —
// including a sign-in already in flight.
//
// The answer is the stored value rather than a flag, because the caller wants
// the key that won and does not care which process minted it.
func (s *Store) SetIfAbsent(ctx context.Context, name, value string) (string, error) {
	// The retry is a fresh transaction, not a second read inside the failed
	// one. Reading again where the insert was refused does not work on any
	// server engine: MySQL and MariaDB fixed the transaction's snapshot at the
	// opening select, before the winner committed, so the read sees nothing;
	// PostgreSQL has already aborted the transaction and refuses every
	// statement after it. Only a new transaction has a view that includes the
	// row the loser collided with.
	//
	// Once more and no further, the same shape a declaration uses: a row that
	// keeps disappearing is not a race and must not become a loop.
	for again := true; ; again = false {
		stored, err := s.setIfAbsent(ctx, name, value)
		if again && database.IsDuplicate(err) {
			continue
		}
		return stored, err
	}
}

// setIfAbsent is one attempt, letting a duplicate out for the caller to take
// again.
func (s *Store) setIfAbsent(ctx context.Context, name, value string) (string, error) {
	db, ok := database.Handle(s.db)
	if !ok {
		return "", fmt.Errorf("this store is already inside a transaction")
	}
	stored := value
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		stored = value
		held := new(Setting)
		switch err := tx.NewSelect().Model(held).Where("name = ?", name).Scan(ctx); {
		case database.IsNoRows(err):
		case err != nil:
			return fmt.Errorf("read the %q setting: %w", name, err)
		default:
			stored = held.Value
			return nil
		}

		if s.beforeInsert != nil {
			s.beforeInsert()
		}
		row := &Setting{Name: name, Value: value, UpdatedAt: s.now().Truncate(time.Microsecond)}
		if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
			// Out whole, so the caller opens a new transaction whose first
			// read can see what the winner committed.
			if database.IsDuplicate(err) {
				return err
			}
			return fmt.Errorf("record the %q setting: %w", name, err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return stored, nil
}

// Duration reads a setting as a length of time, falling back to fallback where
// it is unset or where nobody can parse what is stored.
//
// A value nobody can parse is treated as one nobody set. The alternative is a
// deployment that will not start because a setting somebody typed by hand in
// the database is malformed, which turns a tuning mistake into an outage.
//
// A read that could not complete is returned as an error, never as the
// fallback — see the note on Get.
func (s *Store) Duration(ctx context.Context, name string, fallback time.Duration) (time.Duration, error) {
	raw, set, err := s.Get(ctx, name)
	if err != nil || !set {
		return fallback, err
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return fallback, nil
	}
	return parsed, nil
}

// Count reads a setting as a whole number of things, falling back where it is
// unset, where nobody can parse what is stored, or where what is stored is not
// a positive count.
//
// A read that could not complete is returned as an error, never as the
// fallback — see the note on Get.
func (s *Store) Count(ctx context.Context, name string, fallback int) (int, error) {
	raw, set, err := s.Get(ctx, name)
	if err != nil || !set {
		return fallback, err
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return fallback, nil
	}
	return parsed, nil
}
