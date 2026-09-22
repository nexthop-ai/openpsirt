// Package notify records what somebody is told, and reads it back.
//
// It is the in-app notification area — the one channel that works with nothing
// configured. Everyone has one: a triager sees work arriving, a proposer sees
// a dismissal sent back, an approver sees what waits on them, an administrator
// sees that the tool itself is unwell. What differs by role is the content,
// not the mechanism.
//
// Mail and chat are separate channels behind their own interface, and nothing
// here assumes either exists.
package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Lifetime is how long a notification is worth showing.
//
// The two are not a tidiness distinction, they are the design. An Event
// happened once and is acknowledged by the person it happened to. A Condition
// is true while something is true and clears itself when that stops — a build
// that resumes being scanned should leave the list without anybody dismissing
// it. Treating a condition as an event fills the count with problems that
// already went away, and then nobody reads the count.
type Lifetime string

const (
	// Event is a thing that happened: you were assigned this, your dismissal
	// was sent back, somebody named you.
	Event Lifetime = "event"
	// Condition is a state that holds: this build stopped being scanned, this
	// scan will not parse, this person holds work and has not been seen.
	Condition Lifetime = "condition"
)

// Kind is what happened, as a word the interface knows how to draw. Spelled
// here so a producer and a screen cannot disagree about it.
type Kind string

// Kinds is every kind of notification, in the order they are declared.
//
// Named so that the tables keyed on a kind can be checked against it. There
// was no enumeration, and the table of subject lines was one row short: the
// kind it was missing shipped under the generic fallback, and it is the one
// kind whose whole purpose is a specific sentence.
func Kinds() []Kind {
	return []Kind{
		Assigned, Mentioned, SentBack, BuildQuiet, HoldingAbsent,
		CriticalOnRelease, DisclosureDue, DisclosureNear, StatementRevised,
		ClaimWaiting, SentBackWaiting, DeferralEnding, QueueUntaken,
		ApprovalUndone, ClaimLapsed, BroughtIn, Unanswered,
		VulnerabilityDataStale, RiskUnagreed, InventoryMoved,
		ObligationOpen, ObligationPassed,
	}
}

const (
	// Assigned is work arriving, which is what a triager most wants to notice.
	Assigned Kind = "assigned"
	// Mentioned is somebody named in a note. It is an explicit human
	// action directed at one person — somebody asked a question and is
	// waiting on an answer — which is exactly the category that goes at
	// once.
	Mentioned Kind = "mentioned"
	// SentBack is a dismissal an approver asked more of. It goes straight
	// back into the proposer's queue, so silence would leave it sitting.
	SentBack Kind = "sent-back"
	// BuildQuiet is a build nothing has been filed against for longer than
	// this deployment allows. A condition: it clears when a scan arrives.
	BuildQuiet Kind = "build-quiet"
	// HoldingAbsent is somebody who has not signed in for a while and is
	// still holding work. An idle account holding nothing is harmless;
	// work stuck behind somebody who is not here is the problem, and this
	// is the prompt that makes an administrator realize they have gone.
	HoldingAbsent Kind = "holding-absent"
	// CriticalOnRelease is a critical or actively-exploited issue open
	// against something already shipped, with nothing decided about it.
	//
	// The one alert whose stated purpose is a sentence: "this release has
	// a critical, we need to cut a new one". A condition rather than an
	// event, because what matters is that it is *still* true — it clears
	// when the finding closes or somebody answers it, and neither of those
	// is a thing to be dismissed.
	//
	// Tags only. A branch carrying a critical is ordinary work in
	// progress; the same issue against something customers are running is
	// the case this exists for, and telling them apart is the whole of the
	// signal.
	CriticalOnRelease Kind = "critical-on-release"
	// DisclosureDue is an embargo whose date has arrived with nothing
	// decided.
	//
	// A condition rather than an event, and the distinction carries weight
	// here: reaching the date discloses nothing, so this is a
	// question still waiting for an answer rather than a thing that happened.
	// It clears when the date is moved or the finding is disclosed — which is
	// exactly right, because both of those are somebody answering it.
	DisclosureDue Kind = "disclosure-due"
	// DisclosureNear is an embargo whose date is coming.
	//
	// Its own condition rather than a variant of DisclosureDue, because
	// the two clear differently and a single alert would go on saying
	// "coming" after the date had passed. This one clears when the date
	// arrives — at which point the other opens — or when the embargo is
	// extended past the lead time, which is exactly somebody having acted
	// on it.
	DisclosureNear Kind = "disclosure-near"
	// StatementRevised is a VEX publisher changing what they said about
	// something a standing decision cited.
	//
	// The decision stands: a third party's claim never becomes ours, and a
	// publisher changing their mind does not withdraw somebody's judgment.
	// It says the ground moved under a dismissal approved
	// on the strength of it, which is a condition about evidence rather
	// than an event about a person — the same shape as a build that
	// stopped being scanned, and it clears the same way, when the decision
	// is revisited or the statement is cited no longer.
	StatementRevised Kind = "statement-revised"

	// ObligationOpen is a window this deployment declared, running from the
	// moment an attack on a product became known, with no notice outside
	// recorded against it.
	//
	// A condition from the moment the record stands rather than from a lead
	// time before the end: the windows in force anywhere are a day to a
	// fortnight, and waiting to warn gives back the hours the warning is for.
	// It clears when a notice names the window, when the record is cleared,
	// or when the window is retired — and when the end arrives, at which point
	// the other opens.
	ObligationOpen Kind = "obligation-open"
	// ObligationPassed is the same window after its end, still with no
	// notice recorded against it. Both halves are facts; whether anybody owed
	// anything is not the tool's answer to give.
	ObligationPassed Kind = "obligation-passed"

	// The four things that are wrong because nothing has happened.
	//
	// Conditions, and they have to be: what is wrong is the absence of an
	// event, which is the one thing no message driven by an event can ever
	// report. Each clears by the thing happening — the claim is approved,
	// the proposer revises, the deferral is re-made or lapses, somebody
	// takes the work — and none of them is a thing to be dismissed.
	//
	// ClaimWaiting is a claim that has been waiting on a second person for
	// longer than this deployment allows.
	ClaimWaiting Kind = "claim-waiting"
	// SentBackWaiting is a claim an approver asked more of and nobody has
	// touched since. The queue shows it to neither of them: it is not waiting
	// on the approver, and the proposer's tab lists what is pending.
	SentBackWaiting Kind = "sent-back-waiting"
	// DeferralEnding is a deferral whose end date is coming. What follows the
	// date is the finding returning to somebody's queue, so a warning is worth
	// having before rather than after.
	DeferralEnding Kind = "deferral-ending"
	// QueueUntaken is work sitting in a team's queue that nobody has
	// taken.
	//
	// The one that needed saying, because it is neither owned nor unowned:
	// it sits in a gap where it looks handled and is not, which is the
	// failure the list of work nobody owns exists to prevent, reappearing
	// one team at a time.
	QueueUntaken Kind = "queue-untaken"

	// The two outcomes a proposer is told about. Events, because each is a
	// thing that happened; the rest of what becomes of a claim is on their
	// own view of it, which is where approval staying silent's silence
	// holds.
	//
	// ApprovalUndone is an agreement taken back. It reverses something the
	// proposer was relying on, which is the one outcome nobody expects.
	ApprovalUndone Kind = "approval-undone"
	// ClaimLapsed is a judgment the code moved out from under. It hands work
	// back to somebody who did nothing to cause it, and the alternative is the
	// finding reappearing as though nobody had ever looked at it.
	ClaimLapsed Kind = "claim-lapsed"

	// BroughtIn is somebody granted one undisclosed case.
	//
	// An event, and the one message that names an undisclosed issue on
	// purpose: it goes to the person who has just been given that issue, in
	// the area inside the application, where an undisclosed finding may be
	// named, and a message saying "you were given access to something"
	// without saying to what is unactionable. What leaves this deployment
	// about it still carries a link and nothing else.
	BroughtIn Kind = "brought-in"

	// Unanswered is a report somebody sent us and nobody has replied to.
	//
	// A condition, for the reason the others here are: what is wrong is
	// that nothing has happened. Prompt acknowledgment is the part of
	// coordinated disclosure a reporter actually judges, and it is the
	// step that costs nothing and is missed by being nobody's job — so it
	// is raised from the moment a report is recorded rather than after a
	// threshold, and clears when somebody records that they answered.
	Unanswered Kind = "unanswered-report"

	// The two conditions about the deployment rather than about anybody's
	// work. Both are a report that has to come back empty, asked as a
	// condition instead — because a report that is empty every time is one
	// nobody opens, and mailing it on a schedule cannot tell "the control
	// held" from "the job did not run".
	//
	// VulnerabilityDataStale is the scanner's data having stopped moving.
	// Nothing fails: every scan since answers as confidently as ever, against
	// what was known a month ago, and a finding that newer data would have
	// opened simply has not.
	VulnerabilityDataStale Kind = "vulnerability-data-stale"
	// InventoryMoved is an upload that changed more of a build's contents
	// than this deployment expects one to.
	//
	// An event, and the one thing an upload is worth interrupting anybody
	// for. What it reports happened at a moment and stays true of that
	// moment: the next upload is a different upload rather than a state this
	// one could return from, so there is nothing for a condition to clear.
	//
	// The fact and a link. What moved is a list of component names, which is
	// a screen rather than a sentence, and the screen is where the reading
	// rule is applied.
	InventoryMoved Kind = "inventory-moved"
	// RiskUnagreed is something hidden with nobody's agreement behind it.
	//
	// The one outcome-shaped failure the record cannot find on its own
	// afterwards: the three claims that say no further work is needed each
	// require a second person, so one standing alone means the write path was
	// got around rather than that somebody is behind.
	RiskUnagreed Kind = "risk-unagreed"
)

// Notification is one thing somebody was told.
type Notification struct {
	bun.BaseModel `bun:"table:notification,alias:nt"`

	ID       int64    `bun:"id,pk,autoincrement"`
	PersonID int64    `bun:"person_id,notnull"`
	Kind     Kind     `bun:"kind,notnull"`
	Lifetime Lifetime `bun:"lifetime,notnull"`
	// About names what a condition is about. Empty for an event.
	About string `bun:"about,notnull"`
	// AboutOpen carries the uniqueness: the same value while the condition
	// holds, null once it has cleared. See the migration for why it is a
	// column rather than a partial index.
	AboutOpen *string `bun:"about_open"`
	// Body and Link describe a moment. They are stored rather than derived on
	// read because the finding a line names may since have been decided,
	// closed or reopened, and re-deriving would describe the world now instead
	// of the world somebody was told about.
	Body string `bun:"body,notnull"`
	Link string `bun:"link,notnull"`
	// Private says what this is about has not been disclosed. A channel
	// that leaves this deployment carries a link and nothing else for one
	// of these ; the area inside it is unaffected.
	Private bool `bun:"private,notnull"`
	// ProductID and VulnerabilityID are what this is about, where it is
	// about either. Every read of this table narrows by them, so a row
	// marked private carries a product or is refused.
	ProductID       *int64 `bun:"product_id"`
	VulnerabilityID *int64 `bun:"vulnerability_id"`
	// Concerns is what an event was about, where it was about a finding. Not
	// About above, which carries a condition's identity and deduplicates on
	// it; this is never matched on for uniqueness, and exists so a digest can
	// answer whether somebody was already told.
	Concerns string `bun:"concerns"`
	// Together is what makes one thing said to many people one thing to carry
	// outside. Empty for everything personal, which is most of it.
	Together string `bun:"together,notnull"`
	// SentAt says this has been carried outside the application, and Attempts
	// how many times that has been tried. Unsent is the whole of the work
	// list, so a failure needs no state of its own — it is simply still
	// unsent — and the count is what keeps that from being forever.
	SentAt    *time.Time `bun:"sent_at"`
	Attempts  int        `bun:"attempts,notnull"`
	CreatedAt time.Time  `bun:"created_at,notnull"`
	ReadAt    *time.Time `bun:"read_at"`
	ClearedAt *time.Time `bun:"cleared_at"`
}

// Store records and reads notifications.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

// NewStore returns a store over db, which is the transaction an
// administrative act is being made in or this deployment's pooled handle.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Telling is one thing to tell one person.
type Telling struct {
	PersonID int64
	Kind     Kind
	// About is required for a condition and refused for an event: a condition
	// that cannot say what it is about cannot be cleared when that thing
	// changes, and an event that names one would be silently deduplicated
	// against an unrelated row.
	About string
	Body  string
	Link  string
	// Concerns is what this is about, where it is about a finding. Built by
	// Concerning so that whoever tells and whoever asks later agree on the
	// shape without either of them writing it out.
	Concerns string
	// Together says this sentence is one thing said to many people, and names
	// the thing. Every recipient gets their own row, as they do for every
	// kind; what this decides is that a channel outside this deployment is
	// told once rather than once per reader.
	//
	// Empty where a message is somebody's own — "a decision of yours",
	// "you were named" — because those are as many things as there are
	// people, and collapsing them would carry one and drop the rest.
	Together string
	// Private says what this is about is a finding nobody has announced.
	// It travels with the telling rather than being worked out later: what
	// is said outside this deployment depends on what was true when there
	// was something to say.
	Private bool
	// ProductID and VulnerabilityID say what this is about, and are what
	// every later read narrows by. Required alongside Private, refused
	// otherwise: a row nobody can attribute to a product is one no
	// visibility rule can be applied to.
	ProductID       *int64
	VulnerabilityID *int64
}

// Tell records something that happened, for one person.
//
// Events are not deduplicated. Being assigned the same finding twice is two
// things that happened, and collapsing them would lose the second — which is
// the one the person has not seen.
func (s *Store) Tell(ctx context.Context, t Telling) error {
	if t.PersonID == 0 || t.Kind == "" || t.Body == "" {
		return errors.New("a notification needs somebody, a kind and something to say")
	}
	if t.About != "" {
		return fmt.Errorf("%s: an event is about a moment rather than a state, "+
			"so it takes no subject to clear against", t.Kind)
	}
	if err := attributable(t.Kind, t.Private, t.ProductID); err != nil {
		return err
	}
	row := &Notification{
		PersonID: t.PersonID, Kind: t.Kind, Lifetime: Event,
		Body: t.Body, Link: t.Link, Private: t.Private,
		ProductID: t.ProductID, VulnerabilityID: t.VulnerabilityID,
		Concerns: t.Concerns, Together: t.Together, CreatedAt: s.now(),
	}
	if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
		return fmt.Errorf("record what happened: %w", err)
	}
	return nil
}

// Holds is one condition that is currently true.
type Holds struct {
	// About names the thing, and is what makes two runs of the same pass
	// recognize the same condition rather than opening it again.
	About string
	Body  string
	Link  string
	// Private says the condition is about a finding nobody has announced.
	// Every embargo alert is one; a build that stopped being scanned is not
	// about a finding at all.
	Private bool
	// ProductID and VulnerabilityID say what this is about, on the same
	// terms as a telling: required alongside Private, and what every later
	// read narrows by.
	ProductID       *int64
	VulnerabilityID *int64
}

// Reconcile makes the open conditions of one kind, for one person, exactly
// these — opening what is newly true and clearing what has stopped being true.
//
// This is the whole of it: a condition clears itself and an event is
// acknowledged. The pass that derives a condition does not have to remember
// what it said last time, and
// nobody has to dismiss an alert about a problem that went away: the answer is
// recomputed and the difference is what gets written.
//
// Returns how many were opened and how many cleared, because a pass that
// reports "nothing changed" is how somebody notices it has stopped working.
func (s *Store) Reconcile(ctx context.Context, personID int64, kind Kind,
	holding []Holds) (opened, cleared int, err error) {

	if personID == 0 || kind == "" {
		return 0, 0, errors.New("a condition needs somebody and a kind")
	}
	for _, h := range holding {
		if err := attributable(kind, h.Private, h.ProductID); err != nil {
			return 0, 0, err
		}
	}
	wanted := make(map[string]Holds, len(holding))
	for _, h := range holding {
		if h.About == "" {
			return 0, 0, fmt.Errorf("%s: a condition has to say what it is about", kind)
		}
		wanted[h.About] = h
	}

	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		opened, cleared = 0, 0

		var open []Notification
		if err := tx.NewSelect().Model(&open).
			Where("person_id = ?", personID).
			Where("kind = ?", kind).
			Where("cleared_at IS NULL").
			Scan(ctx); err != nil {
			return fmt.Errorf("read what is already being said: %w", err)
		}

		now := s.now()
		held := make(map[string]bool, len(open))
		for _, row := range open {
			held[row.About] = true
			if still, yes := wanted[row.About]; yes {
				// Still true, and possibly true of more than it was. The
				// sentence is what the condition currently says — how many
				// pieces of work are sitting in a queue, how many places a
				// deferral covers — and a row opened once and never touched
				// again went on saying what was true the first time anybody
				// looked. A queue that grew from three to forty thousand
				// overnight still read "3 pieces of work waiting", which is a
				// count four orders of magnitude out standing beside the queue
				// it is about.
				if row.Body == still.Body && row.Link == still.Link {
					continue
				}
				if _, err := tx.NewUpdate().Model((*Notification)(nil)).
					Set("body = ?", still.Body).
					Set("link = ?", still.Link).
					Where("id = ?", row.ID).Exec(ctx); err != nil {
					return fmt.Errorf("say what a standing condition says now: %w", err)
				}
				continue
			}
			// It stopped being true. The row is kept and marked rather than
			// deleted, so "this cleared" stays answerable and a condition that
			// returns is a new row rather than an edit of an old one.
			if _, err := tx.NewUpdate().Model((*Notification)(nil)).
				Set("cleared_at = ?", now).
				Set("about_open = NULL").
				Where("id = ?", row.ID).Exec(ctx); err != nil {
				return fmt.Errorf("clear a condition that ended: %w", err)
			}
			cleared++
		}

		for about, h := range wanted {
			if held[about] {
				continue
			}
			key := about
			row := &Notification{
				PersonID: personID, Kind: kind, Lifetime: Condition,
				About: about, AboutOpen: &key,
				Body: h.Body, Link: h.Link, Private: h.Private,
				ProductID: h.ProductID, VulnerabilityID: h.VulnerabilityID,
				CreatedAt: now,
			}
			// Each insert stands on its own savepoint, because carrying on
			// after a failed write is not something every engine allows.
			//
			// Another process getting there first is the ordinary case rather
			// than a fault: a deployment runs more than one of these — the
			// chart ships two replicas and every one sweeps — so two saying
			// the same true thing at the same moment is expected, the unique
			// index is what makes it one row, and a duplicate is not
			// retryable, so aborting the sweep would leave every
			// administrator after this one told nothing.
			//
			// But on PostgreSQL a refused statement poisons the whole
			// transaction: everything after it fails and the commit turns
			// itself into a rollback. Simply continuing therefore threw away
			// the clears made above and reported counts for work that had not
			// happened — and it did so only on that one engine, which is why
			// this is a savepoint rather than a bare `continue`. `SAVEPOINT`
			// is plain SQL that all four engines take, so this stays engine
			// agnostic.
			sp, err := tx.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("hold a point to open a condition from: %w", err)
			}
			if _, err := sp.NewInsert().Model(row).Exec(ctx); err != nil {
				_ = sp.Rollback()
				if database.IsDuplicate(err) {
					continue
				}
				return fmt.Errorf("open a condition that became true: %w", err)
			}
			if err := sp.Commit(); err != nil {
				return fmt.Errorf("keep a condition that was opened: %w", err)
			}
			opened++
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return opened, cleared, nil
}

// attributable refuses a private notification that names no product.
//
// The read narrows by product, so a row marked private and attributed to
// nothing is one no visibility rule can be applied to — it would have to be
// shown to everybody or to nobody, and both are wrong. Refusing at the write
// makes that a failure where it is written rather than a leak, or a silent
// disappearance, where it is read.
func attributable(kind Kind, private bool, productID *int64) error {
	if private && (productID == nil || *productID == 0) {
		return fmt.Errorf("%s: a notification about something undisclosed says "+
			"which product it is about, because that is what its readers are "+
			"narrowed by", kind)
	}
	return nil
}

// Waiting is what one person has not dealt with, newest first, and how many
// there are.
//
// A cleared condition is not waiting on anybody: the thing it was about
// stopped being true, which is the answer rather than a task.
//
// Narrowed by what they may read now, not by what they could read when they
// were told (REQ-42 and REQ-43). Somebody whose private-triage on a product
// is withdrawn stops being served the lines naming its undisclosed findings,
// and is served them again if it is granted back — because they were told, and
// the record of having been told is what an auditor wants after a leak. So the
// row is filtered rather than deleted, which the alternative would have been
// and which destroys exactly that.
//
// The count goes through the same conditions as the list. A badge counting
// what the list does not show is the leak reduced to a number, which is still
// the answer to "is there something here about this".
func (s *Store) Waiting(ctx context.Context, subject access.Subject,
	limit, offset int) ([]Notification, int, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		// A pipeline key is not a person and has nothing to be told.
		return nil, 0, nil
	}
	limit = database.AList.Of(limit)

	mine := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("person_id = ?", subject.ID).
			Where("read_at IS NULL").
			Where("cleared_at IS NULL")
		return readable(q, subject)
	}

	total, err := mine(s.db.NewSelect().Model((*Notification)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what is waiting: %w", err)
	}
	var rows []Notification
	if err := mine(s.db.NewSelect().Model(&rows)).
		Order("created_at DESC", "id DESC").
		Limit(limit).Offset(offset).Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("read what is waiting: %w", err)
	}
	return rows, total, nil
}

// readable narrows a read of this table to what the subject may see now.
//
// Here rather than in the handler, because every read of this table is
// narrowed by it and a rule spelled once per caller is a rule that is
// eventually spelled wrong in one of them (REQ-42 and REQ-43).
//
// The rule is that a notification stays readable while the reason it was
// sent still holds, which is not the same question as whether this person
// could read the finding it names. A notification is a message addressed to
// somebody under a rule this deployment wrote down, and the audiences those
// rules name are roles, cases and — for embargo notices alone — administrators
// (`DESIGN-notifications.md`). So the withdrawal that has to take a line away
// is the withdrawal of the reason it arrived.
//
// Four ways a row is readable, and a private row carries a product because the
// write refuses one that does not:
//
//   - It is not about anything undisclosed. Most of the table.
//   - It is about a product where this subject reads undisclosed work now.
//   - It is about an issue they were brought onto one case at a time, which
//     grants that issue and nothing else of the product around it.
//   - They administer the deployment. Not because administering is reading —
//     it is not, and every other read here says so (REQ-42) — but because the
//     embargo notice names administrators as an audience of its own, and a
//     message sent under that rule and then withheld under this one would be
//     written for somebody who cannot open it. An administrator grants roles,
//     so this hands them nothing they could not hand themselves.
func readable(q *bun.SelectQuery, subject access.Subject) *bun.SelectQuery {
	if _, all := subject.Products(); all {
		// The deployment itself, which reads everything by definition.
		return q
	}
	if subject.Admin {
		// Reading their own. An embargo notice names administrators among its
		// audiences (`DESIGN-notifications.md`), so a line addressed to one is
		// theirs to read whatever they hold on the product it is about.
		return q
	}
	return byProduct(q, subject)
}

// byProduct is readable's product half, with no arm for administration.
//
// Separate because administration is not a visibility grant. Reading a list
// addressed to somebody else is the one read of this table that is not the
// reader's own, and there the administrator flag says who may ask rather than
// what the answer contains.
func byProduct(q *bun.SelectQuery, subject access.Subject) *bun.SelectQuery {
	products, all := subject.Products()
	if all {
		return q
	}
	var private []int64
	for _, id := range products {
		if subject.Reads(access.Private, id) {
			private = append(private, id)
		}
	}
	return q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("private = ?", false)
		if len(private) > 0 {
			q = q.WhereOr("product_id IN (?)", bun.List(private))
		}
		// A case grant is one issue in one product, so it is a pair rather
		// than a product: widening it to the product would hand a
		// collaborator the rest of that product's embargo list, which is the
		// whole of what the grant is not.
		for _, product := range subject.CaseProducts() {
			for _, issue := range subject.Cases(product) {
				q = q.WhereOr("(product_id = ? AND vulnerability_id = ?)", product, issue)
			}
		}
		return q
	})
}

// ToldTo is what one person has been told, read by somebody else, newest
// first. Read and cleared rows included: the question this answers is what
// somebody was told, and a line they have already acknowledged is still a line
// they were sent.
//
// For either thing held over the deployment, and refused for anybody else.
// Every other read of this table is somebody reading their own; this one is a
// person page asking after a leak, which is the one reason to read a list
// addressed to somebody else. Enforced here rather than at the handler,
// because that is where the rest of this table's rules live (REQ-42 and
// REQ-43).
//
// Narrowed by what the reader may see, and neither grant is a way to see
// more. Holding one decides who may ask this question; the rows that come
// back are the ones the asker could read on their own account, so somebody
// holding nothing on a product reads the public half of a feed and not the
// embargoed half — and an auditor, who holds no product, reads nothing.
//
// The defense for answering it whole was that an administrator could grant
// themselves the product and read it anyway. They can, and that grant lands in
// the administrative record within seconds, where this read left nothing at
// all — so the two are not equivalent, and the cheaper of them was the silent
// one.
func (s *Store) ToldTo(ctx context.Context, subject access.Subject, personID int64,
	limit, offset int) ([]Notification, int, error) {

	// Either thing held over the deployment, and neither is a way to see
	// more: the rows are narrowed below by what the asker could read on their
	// own account. Somebody who reaches no product is answered with nothing,
	// which is the same answer an administrator holding no product gets.
	if !subject.ReadsTheDeployment() {
		return nil, 0, access.Denied("read what somebody else was told")
	}
	limit = database.AList.Of(limit)

	theirs := func(q *bun.SelectQuery) *bun.SelectQuery {
		return byProduct(q.Where("person_id = ?", personID), subject)
	}
	total, err := theirs(s.db.NewSelect().Model((*Notification)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what they were told: %w", err)
	}
	var rows []Notification
	if err := theirs(s.db.NewSelect().Model(&rows)).
		Order("created_at DESC", "id DESC").
		Limit(limit).Offset(offset).Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("read what they were told: %w", err)
	}
	return rows, total, nil
}

// Acknowledge marks one of somebody's notifications read.
//
// Their own only: the identifier is a number a caller supplies, and a store
// that took it at face value would let anybody mark anybody's list read.
func (s *Store) Acknowledge(ctx context.Context, subject access.Subject, id int64) error {
	if subject.Kind != access.Person || subject.ID == 0 {
		return access.Denied("acknowledge a notification")
	}
	res, err := s.db.NewUpdate().Model((*Notification)(nil)).
		Set("read_at = ?", s.now()).
		Where("id = ?", id).
		Where("person_id = ?", subject.ID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("acknowledge: %w", err)
	}
	// Matched rather than changed: the connection settings make an
	// affected count mean "the row was still there" on all four engines,
	// so zero here means it is not theirs or does not exist — which are
	// the same answer on purpose.
	//
	// That holds only because the update does not also require it to be
	// unread. With that condition, acknowledging something twice reported
	// zero and was refused — so a second click, or a click racing the
	// button that clears everything, answered "no notification of yours by
	// that number" about one plainly theirs. Acknowledging is idempotent
	// instead.
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("acknowledge that notification: %w", err)
	}
	if n == 0 {
		return access.Denied("acknowledge a notification")
	}
	return nil
}

// AcknowledgeAll marks everything somebody is waiting on read.
func (s *Store) AcknowledgeAll(ctx context.Context, subject access.Subject) (int, error) {
	if subject.Kind != access.Person || subject.ID == 0 {
		return 0, access.Denied("acknowledge notifications")
	}
	res, err := s.db.NewUpdate().Model((*Notification)(nil)).
		Set("read_at = ?", s.now()).
		Where("person_id = ?", subject.ID).
		Where("read_at IS NULL").
		Where("cleared_at IS NULL").
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("acknowledge everything: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return 0, fmt.Errorf("acknowledge everything: %w", err)
	}
	return int(n), nil
}

// Concerning names the finding a notification is about.
//
// Identifiers rather than names, for two reasons that both bit. A name is
// spelled differently depending on where it is read — the path a request names
// a product by is not the display name a query returns — so keying on one and
// looking up by the other never matches, and the digest silently repeats
// everything it was meant to leave out. And a name is unbounded: a component
// name comes from a third party's inventory, and three of them concatenated
// overflow a bounded column on every engine but SQLite, where the write fails
// and the person is told nothing at all.
//
// Assignment covers every build of a product holding the same component , so
// the build is deliberately not part of it: being told about one build and
// asked about another is the same piece of work.
func Concerning(productID, vulnerabilityID, componentID int64) string {
	return fmt.Sprintf("%d/%d/%d", productID, vulnerabilityID, componentID)
}
