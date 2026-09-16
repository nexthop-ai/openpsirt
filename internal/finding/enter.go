package finding

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Entering is a flaw somebody is recording in what this deployment ships.
//
// Not something a scanner found. A scanner reports a known issue in a
// component somebody else wrote; this is a vulnerability in our own product,
// usually before anybody outside knows about it — which is why it starts
// undisclosed and why the whole disclosure apparatus hangs off it.
type Entering struct {
	// TargetIDs are the builds it is in. A flaw is in something we shipped,
	// and which releases is the first question anybody asks — usually more
	// than one, because the same code ships on several lines and as several
	// variants at once.
	//
	// **One issue, one finding per build.** That is the shape a scanner's
	// findings already take, so a flaw somebody recorded lists, ranks, comes
	// due, carries decisions and appears in a comparison exactly as one that
	// was reported does — rather than in a scheme of its own that everything
	// downstream would need to know about.
	TargetIDs []int64
	// Component names what in the build carries it, as the build calls it.
	// Empty is the build itself, which is the honest answer where the flaw is
	// in how the pieces are put together rather than in one of them.
	Component string
	// Version and Ecosystem narrow a name that reaches more than one
	// component. A name is not unique within a build — a real switch image
	// ships three vendored versions of one library, and thirteen names in it
	// are held at one version by two components — so a name alone is a
	// question rather than an answer, and the answer to an ambiguous one is a
	// refusal that says which choices there are.
	Version   string
	Ecosystem string
	// Summary is what the flaw is, in the words of whoever found it. It is
	// what a triager reads first and often all they read.
	Summary string
	// Severity is how bad it is judged to be, in the same words a report uses,
	// so that everything ranking and clocking findings treats it the same way.
	//
	// **It may be left unstated.** Somebody recording what they have just
	// found, before anybody has worked out how bad it is, has not decided it
	// is mild — and making them pick a word to get the record written is how
	// a guess ends up stored as a judgment.
	//
	// An unrated finding is carried, listed, assignable and **on the same
	// clock every other unrated finding is**: the deadline windows answer
	// "medium" for a severity they do not recognize, which is what a scanner
	// that rated nothing already gets. That is a deliberate default rather
	// than a gap — a finding with no deadline is one that is never late, and
	// never being late is how something is forgotten.
	Severity string
	// Vector is the CVSS base vector, where somebody has worked one out. The
	// score is derived from it here and never taken alongside it, so the two
	// cannot say different things — the number is what sorts and the vector is
	// what somebody can argue with.
	Vector string
	// Weaknesses is what kind of flaw it is, by the classification the world
	// uses. Recorded because it is what makes a set of findings comparable to
	// anything outside this deployment.
	Weaknesses []string
	// Disclosed says this is already public. The default is that it is not:
	// somebody recording a flaw in their own product before it is announced is
	// the case this exists for, and defaulting the other way makes the
	// dangerous mistake the quiet one.
	Disclosed bool
	// Told is who reported it, where somebody did. Every field of it is
	// optional: a flaw found by whoever is typing has no reporter, and a
	// form demanding one asks them to invent an answer.
	//
	// The day it arrived is what the embargo runs from, which is why it
	// travels with the record rather than being filled in afterwards.
	Told Told
}

// rated is the severity words somebody may record. The same set a report may
// carry, so that a finding a person entered ranks and expires beside the ones a
// scanner found rather than in a scheme of its own.
var rated = func() map[string]bool {
	set := map[string]bool{}
	for _, word := range Recordable() {
		set[word] = true
	}
	return set
}()

// ErrNoSuchComponent says the build holds nothing by that name.
var ErrNoSuchComponent = errors.New("this build holds nothing by that name")

// ErrNothingSaid says a recorded finding arrived without a summary.
//
// A sentinel because it is the caller's to fix. Whitespace passes a minimum
// length and is not a summary, so this is reachable from a request rather than
// only from a caller inside this process.
var ErrNothingSaid = errors.New("a recorded finding has to say what the flaw is")

// ErrNothingScanned says the build holds no contents to record against.
var ErrNothingScanned = errors.New(
	"nothing has been scanned into this build, so there is nothing to record against")

// Enter records a flaw in what a build ships, and returns the finding and the
// identifier it was filed under.
//
// **It is filed under an identifier this deployment mints**, because there is
// nothing else to file it under: a flaw nobody has published has no CVE, and
// waiting for one would mean the record of what we knew starts after the work
// does. The identifier is the product's own name, the year, and a number —
// `SONIC-2026-481907` — which is the shape a vendor advisory already takes.
// The number is drawn rather than counted, so it is not a running total of
// what this product has kept quiet.
// When a CVE is assigned later it is recorded as another name for the same
// issue, and the issue is then filed under the CVE; nothing about the finding,
// the decisions or the approvals moves, because they are keyed on the issue
// rather than on what it is called.
//
// **It opens with no run**, and everything that asks when a finding opened
// reads the row rather than the run. A scan will not close it either: a run is
// the authority on what it found, and it found none of this.
func (s *Store) Enter(ctx context.Context, subject access.Subject, in Entering) ([]Finding, string, error) {
	if len(in.TargetIDs) == 0 {
		return nil, "", ErrNoBuild
	}
	// One product, because an identifier is minted per product and a flaw
	// recorded across two would have to be two records. Read from the builds
	// rather than taken from the caller, and disagreement is refused rather
	// than resolved by taking the first.
	productID, err := productOf(ctx, s.db, in.TargetIDs[0])
	if err != nil {
		return nil, "", err
	}
	for _, target := range in.TargetIDs[1:] {
		other, err := productOf(ctx, s.db, target)
		if err != nil {
			return nil, "", err
		}
		if other != productID {
			return nil, "", ErrSeveralProducts
		}
	}

	// Recording a flaw in our own product is triage work on a finding nobody
	// has disclosed, so it asks for the right that names that. Public triage
	// is not enough: somebody who may argue about known issues in shipped
	// components has not been given the undisclosed ones.
	visibility := access.Private
	if in.Disclosed {
		visibility = access.Public
	}
	// The same composition every other triage decision uses: an undisclosed
	// finding asks for the private right, and a public one is covered by
	// either. Somebody trusted with what nobody has announced is certainly
	// trusted with what everybody has, and spelling that a second way here
	// would be a second rule to keep in step with the first.
	if !subject.Triages(visibility, productID) {
		return nil, "", access.Denied(
			fmt.Sprintf("record a finding in product %d", productID))
	}
	if subject.ID == 0 {
		return nil, "", access.Denied("record a finding without being anybody")
	}
	if strings.TrimSpace(in.Summary) == "" {
		return nil, "", ErrNothingSaid
	}
	// The same submission policy a justification goes through. It is our
	// own prose, written here and rendered as markdown where it is read
	// back, so the rule that decides what a link may be and refuses raw
	// HTML applies to it exactly as it does to the words beside it — and
	// the bound on how long a rendered field may be comes with it, which
	// this had none of at all.
	if err := markdown.Check(in.Summary); err != nil {
		return nil, "", err
	}
	// The vector first, because it can settle the severity. Scored here rather
	// than taken as a number beside the vector, so that a stated vector and a
	// stated score cannot disagree with nothing to say which was meant.
	scored, err := Score(in.Vector)
	if err != nil {
		return nil, "", err
	}

	severity := strings.ToLower(strings.TrimSpace(in.Severity))
	if severity == "" && scored != nil {
		// Worked out rather than asked for. Somebody who has done the analysis
		// has already answered this, and asking again invites a word that
		// disagrees with the vector beside it.
		severity = scored.Severity
	}
	if severity != "" && !rated[severity] {
		// Checked against the words rather than folded through Band, which is
		// what a *report* goes through. Band answers "medium" for anything it
		// does not recognize, deliberately: a scanner that rated nothing is
		// silent, and silence is not a claim that something is mild. A person
		// typing "urgent" is not silent — they are wrong, and folding it would
		// replace their judgment with one nobody made.
		return nil, "", fmt.Errorf("%q is not a severity", in.Severity)
	}

	type at struct {
		target    int64
		component int64
		name      string
		// Where the component sits in that build, which is what a decision is
		// keyed on. One entry per place, because a component can sit in more
		// than one at once.
		consumerID int64
		consumer   string
	}

	var rows []Finding
	var identifier string
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// The moment, taken on every attempt. It decides the year the
		// identifier is minted in and every timestamp written, and a retry
		// crossing midnight would otherwise file a flaw under last year.
		now := s.now().UTC().Truncate(time.Microsecond)
		// Resolved in every build, inside the transaction that writes
		// the rows. A name one build holds and another does not is a
		// question about which builds are affected — so it is refused,
		// naming the build, rather than recorded against some of them
		// and silently not the rest.
		//
		// And read here rather than handed in, because a retry re-runs
		// this against a database that has moved: a scan landing
		// between two attempts can take a component out of a build,
		// and the row would still have been written, filing a flaw at
		// a place the build no longer holds. Each of these is one
		// indexed lookup, so asking again costs about what carrying
		// the answer in did.
		places := make([]at, 0, len(in.TargetIDs))
		for _, target := range in.TargetIDs {
			componentID, componentName, err := carrying(ctx, tx, target, in)
			if err != nil {
				return err
			}
			// Where it sits, read from the same graph a scan reads. A flaw a
			// person records and the same flaw a scan finds are one thing, so
			// they are keyed the same way — and a place recorded as "directly
			// under the product" when the component is nested is a key no
			// scanned row will ever share, which is two findings and two
			// decisions for one flaw.
			sittings, err := sittingsOf(ctx, tx, target, componentID)
			if err != nil {
				return err
			}
			for _, sitting := range sittings {
				places = append(places, at{
					target: target, component: componentID, name: componentName,
					consumerID: sitting.consumerID, consumer: sitting.consumer,
				})
			}
		}

		// The product, read again in here. It was resolved before the
		// transaction for the refusal — a request is authorized before a name
		// in it is resolved, so that read has to stay — and then used inside
		// to mint the identifier, to name the product in it, and to read the
		// triage floor. A retry runs against a database where a stream may
		// have been re-pointed, and the identifier would have been minted
		// from a product that is gone, under an authorization taken against
		// it. Refused rather than guessed at, the way widening a flaw's build
		// set is.
		if still, err := productOf(ctx, tx, in.TargetIDs[0]); err != nil {
			return err
		} else if still != productID {
			return fmt.Errorf("the builds changed products while this was being written; try again")
		}

		product, err := productNameOf(ctx, tx, productID)
		if err != nil {
			return err
		}
		// Minted inside the transaction. The number is one past the
		// highest this product has issued this year, and reading it
		// before the transaction began would describe a world another
		// writer has since moved.
		identifier, err = mint(ctx, tx, product, now.Year())
		if err != nil {
			return err
		}
		named := Named{
			Identifier:  identifier,
			Severity:    severity,
			Description: in.Summary,
			Weaknesses:  cleaned(in.Weaknesses),
		}
		if scored != nil {
			named.Vector = scored.Vector
			named.Score = float64(scored.ScoreCenti) / 100
		}
		interned, err := NewVulnerabilities(tx).Intern(ctx, []Named{named})
		if err != nil {
			return err
		}
		vulnerabilityID := interned[identifier]

		windows, err := LoadWindows(ctx, tx)
		if err != nil {
			return err
		}
		embargo, err := setting.NewStore(tx).Duration(ctx,
			setting.DiscloseAfter, setting.DefaultDiscloseAfter)
		if err != nil {
			return err
		}
		floor, err := FloorFor(ctx, tx, productID)
		if err != nil {
			return err
		}

		// One row per place in every build, all pointing at the one issue.
		// Every one of them gets the same embargo, rank and deadline: they
		// are the same flaw, and a deadline that differed per build would be
		// the tool deciding that one release matters more.
		rows = make([]Finding, 0, len(places))
		for _, place := range places {
			row := Finding{
				TargetID: place.target, Kind: Entered, Visibility: visibility,
				VulnerabilityID: vulnerabilityID,
				ComponentID:     place.component,
				ConsumerID:      optional(place.consumerID),
				PlaceIdentity:   PlaceIdentity(place.name, place.consumer),
				LastChangedAt:   now,
				OpenedAt:        now,
			}
			// An embargo gets an end. A public finding gets none —
			// it is already disclosed, and a date on it would be a
			// deadline for something that has already happened.
			//
			// Counted from when the report arrived, where somebody
			// said when that was. A report arriving on 1 June and
			// typed in on 15 June otherwise puts our clock two
			// weeks behind the one the reporter has a publication
			// scheduled against — and they are the party who will
			// publish regardless, so ours is the clock that is
			// wrong. It falls back to now, which is every flaw we
			// found ourselves.
			if visibility == access.Private {
				from := now
				if received := in.Told.When(); received != nil {
					from = received.UTC()
				}
				at := from.Add(embargo)
				row.DiscloseAt = &at
			}
			// Ranked and clocked exactly as a scanned finding is, from the
			// same signals. A finding that sorted or expired differently
			// because a person typed it would be a second policy nobody chose.
			ranked := Ranked{Shipped: true}
			if row.Urgency = int64(ranked.Rank()); floor.Admits(false, severity) {
				due := now.Add(windows.For(false, severity))
				row.DueAt = &due
			}
			rows = append(rows, row)
		}
		if _, err := tx.NewInsert().Model(&rows).Exec(ctx); err != nil {
			return fmt.Errorf("record the finding: %w", err)
		}
		// Who told us, in the same transaction as the flaw itself. A
		// report written afterwards is one that can be lost while the
		// finding stands, and the reporter is the party a coordinated
		// timeline is evidenced to. Written through the transaction
		// rather than through the store, because the store holds a
		// database and this is inside one of its transactions.
		if told := in.Told; told.Stated() {
			row := &WhoTold{
				VulnerabilityID: vulnerabilityID,
				// The product it was reported against, which is what decides
				// who may read the reporter's name and address later.
				ProductID:  productID,
				ReportedBy: strings.TrimSpace(told.ReportedBy),
				Contact:    strings.TrimSpace(told.Contact),
				Credit:     strings.TrimSpace(told.Credit),
				ReceivedOn: told.When(),
				RecordedBy: subject.ID,
				RecordedAt: now,
			}
			if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
				return fmt.Errorf("record who told us: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return rows, identifier, nil
}

// ErrNoBuild and ErrSeveralProducts are the two ways the set of builds can be
// wrong, and they are told apart because the answers differ: one is "say where
// this is" and the other is "that is two records, not one".
var (
	ErrNoBuild         = errors.New("say which builds ship it")
	ErrSeveralProducts = errors.New(
		"those builds are of different products, and an identifier is minted per product — " +
			"record it once for each")
)

// carrying resolves what in the build holds the flaw, defaulting to the build
// itself.
func carrying(ctx context.Context, db bun.IDB, targetID int64, in Entering) (int64, string, error) {
	name := strings.TrimSpace(in.Component)
	if name != "" {
		// The resolver every other component lookup already goes through,
		// rather than a second one here. This took the first row a name
		// matched, which is the guess that was measured wrong elsewhere: three
		// vendored versions of one library all resolved to the same component,
		// so a flaw recorded against one of them was filed against whichever
		// had been interned first and nothing said so. An ambiguous name is
		// now a refusal carrying the choices.
		id, err := graph.ComponentAsIn(ctx, db, targetID, name,
			strings.TrimSpace(in.Version), strings.TrimSpace(in.Ecosystem))
		switch {
		case errors.Is(err, graph.ErrNoComponent):
			return 0, "", ErrNoSuchComponent
		case err != nil:
			return 0, "", err
		}
		// Named, and it is what the build is. Keyed with no name like the
		// branch below, because it is the same place: the root's name differs
		// per variant, and a place keyed on it is a different place in each
		// of them.
		root, err := isRootIn(ctx, db, targetID, id)
		if err != nil {
			return 0, "", err
		}
		if root {
			return id, "", nil
		}
		return id, name, nil
	}

	// The build itself. A flaw in how the pieces fit together belongs on the
	// thing that assembles them, and every build has a root — that is what the
	// inventory describes.
	//
	// The root is returned with no name. The product's name differs per
	// variant, so a place keyed on it is a different place in each of them:
	// one flaw across three variants became three places and three decisions.
	// The scan path collapses a root to no name for the same reason.
	var root struct {
		ID int64 `bun:"id"`
	}
	err := db.NewSelect().
		TableExpr(`graph_node AS "n"`).
		Join(`JOIN component AS "c" ON c.id = n.component_id`).
		ColumnExpr(`c.id AS "id"`).
		Where("n.target_id = ?", targetID).
		Where("n.closed_scan_id IS NULL").
		Where("n.is_root = ?", true).
		Limit(1).
		Scan(ctx, &root)
	if database.IsNoRows(err) {
		return 0, "", ErrNothingScanned
	}
	if err != nil {
		return 0, "", fmt.Errorf("look up what this build is: %w", err)
	}
	return root.ID, "", nil
}

// isRootIn says whether a component is what a build is, rather than something
// the build contains.
func isRootIn(ctx context.Context, db bun.IDB, targetID, componentID int64) (bool, error) {
	found, err := db.NewSelect().
		TableExpr(`graph_node AS "n"`).
		Where("n.target_id = ?", targetID).
		Where("n.component_id = ?", componentID).
		Where("n.closed_scan_id IS NULL").
		Where("n.is_root = ?", true).
		Count(ctx)
	if err != nil {
		return false, fmt.Errorf("look up whether that is the build itself: %w", err)
	}
	return found > 0, nil
}

// mint issues an identifier for a flaw recorded against this product.
//
// Shaped like a vendor advisory identifier because that is what it becomes:
// the product, the year, and a number. **The number is drawn rather than
// counted**. Counting from one made the identifier a running total of what
// this product has kept quiet — anybody could ask for the first one, walk
// upward until the answers changed, and read off both how many undisclosed
// flaws exist and when the last one was recorded. That is a disclosure made by
// the name alone, before any route is asked anything.
//
// Drawn from a source fit for the purpose, because guessing the next one is
// the whole of what this prevents. A collision is answered by drawing again
// inside the same transaction, so two people recording at the same moment
// cannot be handed the same identifier: the second waits, sees the first's
// row, and draws once more.
func mint(ctx context.Context, tx bun.Tx, product string, year int) (string, error) {
	prefix := strings.ToUpper(strings.TrimSpace(product))
	if prefix == "" {
		return "", fmt.Errorf("a product with no name cannot issue an identifier")
	}
	// Six digits, kept to a fixed width so every identifier this
	// deployment issues reads the same length. The width is not what makes
	// it unguessable — the routes answer a name somebody holds and a name
	// nobody holds identically — it is what stops the sequence from being
	// readable.
	const lowest, span = 100000, 900000
	for attempt := 0; attempt < 8; attempt++ {
		drawn, err := rand.Int(rand.Reader, big.NewInt(span))
		if err != nil {
			return "", fmt.Errorf("draw an identifier: %w", err)
		}
		candidate := fmt.Sprintf("%s-%d-%d", prefix, year, drawn.Int64()+lowest)
		taken, err := tx.NewSelect().
			TableExpr(`vulnerability AS "v"`).
			Where("v.identifier = ?", candidate).
			Count(ctx)
		if err != nil {
			return "", fmt.Errorf("read whether that identifier is spoken for: %w", err)
		}
		if taken == 0 {
			return candidate, nil
		}
	}
	// Eight collisions in a row against a space this size is not luck, and
	// carrying on would be a loop nobody is watching.
	return "", fmt.Errorf(
		"no identifier could be drawn for %s in %d — the ones it issues are nearly all taken",
		prefix, year)
}

// productNameOf reads what a product is called, for the identifiers it issues.
func productNameOf(ctx context.Context, db bun.IDB, productID int64) (string, error) {
	var name string
	err := db.NewSelect().
		TableExpr(`product AS "p"`).
		ColumnExpr("p.name").
		Where("p.id = ?", productID).
		Scan(ctx, &name)
	if err != nil {
		return "", fmt.Errorf("look up what product %d is called: %w", productID, err)
	}
	return name, nil
}

// ComponentName reads what one component is called, for an answer that has to
// name what it just recorded against.
func (s *Store) ComponentName(ctx context.Context, componentID int64) (string, error) {
	var name string
	err := s.db.NewSelect().
		TableExpr(`component AS "c"`).
		ColumnExpr("c.name").
		Where("c.id = ?", componentID).
		Scan(ctx, &name)
	if err != nil {
		return "", fmt.Errorf("look up what component %d is called: %w", componentID, err)
	}
	return name, nil
}

// cleaned is the weaknesses as they will be stored: trimmed, upper-cased and
// without repeats or empties.
//
// Kept as whatever classification somebody typed rather than checked against a
// catalog of them. A list that refused an identifier it had not heard of
// would refuse next year's, and what this is for is making a set of findings
// comparable to things outside — which is served by recording what was meant
// and not by having an opinion about it.
func cleaned(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, one := range in {
		one = strings.ToUpper(strings.TrimSpace(one))
		if one == "" || seen[one] {
			continue
		}
		seen[one] = true
		out = append(out, one)
	}
	return out
}
