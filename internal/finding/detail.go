package finding

// Everything held about one issue in one component of one build.
//
// A different question from the list, and the one a person is looking at when
// they decide: not "what is open here" but "what do I know about this". It
// gathers what the scanners said, what was claimed before, where the component
// sits and who is holding it — which is why it is long, and why it is not the
// list's code.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Measured is what produced a finding: the run, and what it was measured with.
//
// A build reporting nothing wrong and a build last measured against a
// vulnerability database from March look identical without it, and they are
// not the same statement at all.
type Measured struct {
	Scanner         string
	ScannerVersion  string
	DatabaseVersion string
	// RanHere says we ran it, rather than a build sending us what its own
	// scanner found. Counts are only comparable between builds measured the
	// same way.
	RanHere bool
	// RanAt is when that run finished, which is nil for one still going.
	RanAt *time.Time
}

// Evidence is everything held about one issue in one component here.
//
// Assembled for somebody who has to decide about it and has a thousand more
// waiting. The measure it is built against: nothing here should send them to a
// search engine. If we hold the write-up, the score, the patch, or the version
// that fixes it, it is in this answer.
type Evidence struct {
	Vulnerability string
	Aliases       []string
	Severity      string
	// ScoreCenti and Vector are the severity as a number and the statement of
	// what that number assumes. Network-reachable and unauthenticated is a
	// different judgment from local-and-privileged at the same score.
	ScoreCenti int
	Vector     string
	// Exploited and LikelihoodPPM are what separate the handful that matter
	// from the thousands that can wait.
	Exploited     bool
	LikelihoodPPM int
	Weaknesses    []string
	Description   string
	Advisory      string
	// References are everything the data points at, with patches told apart —
	// somebody deciding whether to backport rather than upgrade needs the
	// change itself, and hunting for it by hand is the step that does not
	// happen when a thousand findings are waiting.
	References []Reference
	// Links are worked out from the names held here rather than supplied by a
	// scanner, which is why they are kept apart from References. What a report
	// points at is whatever its data carried; these resolve because an
	// identifier names a record and a package identifier names a package.
	Links []Link

	// Assessed is what we say instead of the published rating, where
	// somebody has said something. Both are carried, because showing only
	// ours would read as the world's.
	Assessed  string
	Component string
	Version   string
	Upstream  string
	// FixState, FixedIn and FixedAt are what upstream has done about it, which
	// is the difference between "decide whether this matters" and "take the
	// next version".
	FixState FixState
	FixedIn  string
	FixedAt  *time.Time
	// ArrivedFrom is the version this place held before, where the version
	// moved and the issue came with it. Its presence says somebody bumped this
	// and the bump did not resolve it — which is aimed at whoever did the
	// bump rather than at whoever triages.
	ArrivedFrom string
	// Recorded says a person entered this rather than a scanner reporting
	// it, which is what decides whether a person may close it. Everything
	// else about it behaves the same, so this is the one place the
	// difference has to be visible.
	Recorded bool
	// Undisclosed says this has not been announced and DiscloseAt when the
	// embargo ends. The finding screen's standing notice is what somebody
	// has to be unable to miss before saying anything about it.
	Undisclosed bool
	DiscloseAt  *time.Time
	// RoutedBy names the standing rule that placed this, where a rule did
	// rather than a person. A placement nobody can explain is one nobody
	// can correct.
	RoutedBy string
	// Tags are the words somebody put on this, as they were typed.
	Tags []string
	// DueAt is the earliest deadline among these places, which is the one
	// that makes the whole finding late — and NoDeadline says why there is
	// none where there is none. Blank, the screen would read as missing
	// data on the one row somebody is deciding about.
	DueAt      *time.Time
	NoDeadline NoDeadline
	// OpenedAt is when the earliest of these places first appeared here,
	// and FoundBy what produced it: which scanner, at which version,
	// against which vulnerability database.
	//
	// **The run that answered is not the run that answers now**, so this
	// cannot be worked out again later — it is a fact about a moment, like the
	// version a place held before it moved, which is what makes storing it the
	// permitted kind of derivation. Without it, "which scanner and which
	// vulnerability database produced the finding you dismissed on 3 March"
	// has no answer, and a feed that shipped bad data for a week leaves a
	// population of work nothing can identify.
	OpenedAt time.Time
	FoundBy  *Measured

	// What the ecosystem's own index says is newest, and when it shipped .
	// Empty where asking is turned off, where nothing has asked yet, and
	// where the index has never heard of the component.
	LatestVersion    string
	LatestReleasedAt *time.Time
	// NothingSince says upstream has shipped nothing since the year this issue
	// was named, and there is no fix. Two dates compared, not a judgment about
	// anybody's project: it is the reason there is no fix rather than a claim
	// that the project is dead.
	NothingSince bool
	// Places is where it sits here — the consumer that pulls the component in,
	// and whether the build has already argued that place away.
	Places []Sitting
	// AssignedTo is who is dealing with this, by sign-in identity, or empty
	// where nobody is. One name for the whole finding, because assignment is
	// set for a group at once; where the places somehow disagree it is empty
	// rather than naming one of them.
	AssignedTo string
	// Matched says how the scanner reached this, and MatchedFrom where that
	// match came from. One answer for every place, because they all come from
	// one line of a scanner's report.
	//
	// The source is here rather than on the issue because one issue reached
	// through two ecosystems has two answers and the issue can hold one. An
	// Alpine package linking to Debian's tracker is what the other way looks
	// like.
	Matched     Matched
	MatchedFrom string
	// MatchedIn and MatchedRange are the evidence for the judgment Matched
	// asks for: which body of data answered, and the version range the match
	// fired on. A range naming no packaging revision, read beside a version
	// that has one, is the whole argument in a line.
	MatchedIn    string
	MatchedRange string
}

// placesOf folds the open rows of one finding into the places it sits at, one
// entry per place, each with the way down to it.
//
// A place is what a decision is keyed on, so two rows that share a key are one
// thing to answer about and one row to read. Two rows do share one where an
// inventory describes the same consumer twice — the same name and version as a
// source package and as the distribution's package are two components by
// content and one pair of names, which is the key — and usually only one of
// the two is reachable from the root. Listing both drew one way down twice,
// reported the second as though nothing placed the component, and stated a
// scope one larger than the submit then recorded.
//
// No query in it, for the reason evidenceFrom has none.
func placesOf(rows []evidenceRow, chains map[int64][]graph.Step,
	shipped map[int64]string) []Sitting {

	places := make([]Sitting, 0, len(rows))
	at := make(map[string]int, len(rows))
	for _, row := range rows {
		// Down to the consumer, then this component under it. Where the build
		// pulls the component in directly there is no consumer, and the chain
		// down to the component itself is the whole of the answer.
		var walked []graph.Step
		here := graph.Step{Name: row.Component, Version: shipped[row.ComponentID]}
		if row.ConsumerID != nil {
			if down, ok := chains[*row.ConsumerID]; ok && len(down) > 0 {
				walked = append(append([]graph.Step{}, down...), here)
			}
		} else if down, ok := chains[row.ComponentID]; ok && len(down) > 0 {
			walked = append([]graph.Step{}, down...)
		}
		if seen, ok := at[row.PlaceIdentity]; ok {
			// The way down of whichever of them the graph could walk, and the
			// build's own argument only where it covers every row the key
			// folds: an argument about one of two components is not an
			// argument about the place.
			if len(places[seen].Chain) == 0 {
				places[seen].Chain = walked
			}
			places[seen].Suppressed = places[seen].Suppressed && row.Suppressed
			// A claim standing on either row stands at the place. A decision
			// is keyed on the place and expires on the versions, and two rows
			// of one place need not hold the same ones — the source package
			// and the distribution's package of one name differ by a
			// packaging revision — so a decision matches one row and not the
			// other. Keeping the first row's answer dropped a claim somebody
			// had just made, and offered the place again. Lowest identifier
			// wins, so every engine answers alike.
			if row.Decision != nil &&
				(places[seen].Decision == nil || *row.Decision < *places[seen].Decision) {
				places[seen].Decision, places[seen].Claim = row.Decision, row.Claim
			}
			continue
		}
		at[row.PlaceIdentity] = len(places)
		places = append(places, Sitting{
			PlaceIdentity: row.PlaceIdentity,
			Component:     row.Component, Consumer: row.Consumer,
			Suppressed: row.Suppressed, Decision: row.Decision, Claim: row.Claim,
			Urgency: row.Urgency, Chain: walked,
		})
	}
	return places
}

// evidenceFrom is what a reader is shown about a finding, from the places it
// sits at and the four things looked up about it.
//
// No query in it, which is the point: the two rules that are easy to get
// wrong — any place answers about what the scanner matched, and disclosure is
// asked of every place, because one undisclosed place among fifty makes the
// whole of it undisclosed for anybody deciding what may be said — are
// checkable without a database.
func evidenceFrom(rows []evidenceRow, issue Vulnerability, component graph.Component,
	aliases []Alias, references []Reference, weaknesses []Weakness) *Evidence {

	evidence := &Evidence{
		Vulnerability: issue.Identifier, Severity: issue.Severity,
		Assessed: issue.Rated,
		Vector:   issue.Vector, Exploited: issue.Exploited,
		Description: issue.Description, Advisory: issue.Advisory,
		References: references,
		Component:  component.Name, Version: component.Version,
		FixState: FixState(rows[0].FixState), FixedIn: rows[0].FixedIn, FixedAt: rows[0].FixedAt,
		ArrivedFrom: rows[0].ArrivedFrom,
	}
	// Any place answers. They all come from one line of a scanner's report,
	// which the applier writes to every place of the group.
	evidence.Matched = Matched(rows[0].Matched)
	evidence.Recorded = Kind(rows[0].Kind) == Entered
	// Any place answers about the kind; disclosure is asked of all of them,
	// because one undisclosed place among fifty makes the whole of it
	// undisclosed for anybody deciding what may be said.
	for _, row := range rows {
		if access.AsVisibility(row.Visibility) == access.Private {
			evidence.Undisclosed = true
		}
		if row.DiscloseAt != nil &&
			(evidence.DiscloseAt == nil || row.DiscloseAt.Before(*evidence.DiscloseAt)) {
			evidence.DiscloseAt = row.DiscloseAt
		}
	}
	evidence.MatchedFrom = rows[0].MatchedFrom
	evidence.MatchedIn = rows[0].MatchedIn
	evidence.MatchedRange = rows[0].MatchedRange
	if component.LatestVersion != nil {
		evidence.LatestVersion = *component.LatestVersion
	}
	evidence.LatestReleasedAt = component.LatestReleasedAt
	if component.LatestReleasedAt != nil && FixState(rows[0].FixState) != FixedUpstream {
		evidence.NothingSince = currency.NothingSince(
			issue.Identifier, *component.LatestReleasedAt)
	}
	if issue.ScoreCenti != nil {
		evidence.ScoreCenti = *issue.ScoreCenti
	}
	if issue.LikelihoodPPM != nil {
		evidence.LikelihoodPPM = *issue.LikelihoodPPM
	}

	if component.UpstreamVersion != "" {
		evidence.Upstream = component.UpstreamName + " " + component.UpstreamVersion
	}
	for _, alias := range aliases {
		if alias.Identifier != issue.Identifier {
			evidence.Aliases = append(evidence.Aliases, alias.Identifier)
		}
	}
	for _, weakness := range weaknesses {
		evidence.Weaknesses = append(evidence.Weaknesses, weakness.CWE)
	}
	// Worked out here rather than stored: an address derived from two names
	// cannot go stale while the names are right, and storing it would be a
	// second copy of the templates to keep in step.
	evidence.Links = links(issue.Identifier, evidence.Aliases, component.Purl)
	return evidence
}

// versionsOf reads the version each of these components ships at, in one
// statement.
func (s *Store) versionsOf(ctx context.Context, ids []int64) (map[int64]string, error) {
	if len(ids) == 0 {
		return map[int64]string{}, nil
	}
	var rows []struct {
		ID      int64  `bun:"id"`
		Version string `bun:"version"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`c.id AS "id"`).
		ColumnExpr(`c.version AS "version"`).
		Where("c.id IN (?)", bun.List(ids)).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what those ship at: %w", err)
	}
	out := make(map[int64]string, len(rows))
	for _, row := range rows {
		out[row.ID] = row.Version
	}
	return out, nil
}

// Sitting is one place a component occupies, as a finding presents it.
type Sitting struct {
	// PlaceIdentity is what a decision is made against, and what a request
	// names when making one.
	PlaceIdentity string
	// Component is which package of the fold this place is. A fold covers
	// every binary one source package was built at one version, so a place
	// named only by its consumer leaves a reader unable to tell one from
	// another.
	Component  string
	Consumer   string
	Suppressed bool
	Urgency    int64
	// Decision is the claim already standing here, where one does. Once
	// one judgment can cover a chosen subset of places, a finding half
	// answered has to look different from one nobody has touched —
	// otherwise the places left open are invisible and somebody answers
	// them twice or not at all .
	//
	// Not the same as Suppressed, which is the build's own argument in its VEX
	// documents: a different claim by a different author.
	Decision *int64
	// Claim is the action that decision was one row of. A claim covering
	// several places can then name them rather than only count them: "one
	// location" says how big a judgment was and not which code it was about,
	// and on a finding that is only partly decided that is the whole question.
	Claim *int64
	// Chain is the way down to here, the build first and this component
	// last, with a version at every step.
	//
	// The direct consumer is what a decision is keyed on and it is not
	// enough to *read*: where a component is reached several ways the
	// consumer is often the same word twice, and two identical rows do not
	// distinguish two places. the complete chain on a finding asks for the
	// whole chain for that reason. It stays display-only — putting it back
	// into identity is what the place identity was measured against and
	// rejected for, at 49,170 paths against 48 consumers.
	//
	// Empty where the build's inventory left this component unplaced,
	// which is a real state and not an error: a producer that names no
	// root, or a component nothing was recorded as pulling in.
	Chain []graph.Step
}

// evidenceRow is one open place of the fold a finding screen is about.
//
// Named rather than written inline because the assembly that reads it is a
// function of its own: what a reader is shown is worked out from these rows
// and four lookups, with no query in it, which is what makes the rules it
// holds — any place answers about the match, and disclosure is asked of all of
// them — checkable without a database.
type evidenceRow struct {
	PlaceIdentity string     `bun:"place_identity"`
	Consumer      string     `bun:"consumer"`
	ConsumerID    *int64     `bun:"consumer_id"`
	Component     string     `bun:"component"`
	ComponentID   int64      `bun:"component_id"`
	Decision      *int64     `bun:"decision"`
	Claim         *int64     `bun:"claim"`
	Suppressed    bool       `bun:"suppressed"`
	Urgency       int64      `bun:"urgency"`
	FixState      string     `bun:"fix_state"`
	FixedIn       string     `bun:"fixed_in"`
	FixedAt       *time.Time `bun:"fixed_at"`
	Matched       string     `bun:"matched"`
	Kind          string     `bun:"kind"`
	MatchedFrom   string     `bun:"matched_from"`
	MatchedIn     string     `bun:"matched_in"`
	MatchedRange  string     `bun:"matched_range"`
	ArrivedFrom   string     `bun:"arrived_from"`
	Visibility    string     `bun:"visibility"`
	DiscloseAt    *time.Time `bun:"disclose_at"`
	OpenedAt      time.Time  `bun:"opened_at"`
	OpenedRunID   *int64     `bun:"opened_run_id"`
	DueAt         *time.Time `bun:"due_at"`
}

// Detail reads everything held about one issue in one component of a build.
func (s *Store) Detail(ctx context.Context, subject access.Subject, targetID, vulnerabilityID,
	componentID int64) (*Evidence, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	// Asked about the issue rather than about the product, because a
	// collaborator reads one issue here and nothing else.
	visible := access.VisibleOn(subject, productID, vulnerabilityID)
	if !access.SeesOn(subject, productID, vulnerabilityID) || len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	var rows []evidenceRow
	err = s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN component AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN component AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`COALESCE(uc.name, '') AS "consumer"`).
		ColumnExpr(`f.consumer_id AS "consumer_id"`).
		// Which package of the fold this place is. A fold covers every binary
		// one source package was built at one version, so a place named only
		// by its consumer would leave a reader unable to tell curl's from
		// libcurl4t64's.
		ColumnExpr(`c.name AS "component"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`f.visibility AS "visibility"`).
		ColumnExpr(`f.disclose_at AS "disclose_at"`).
		// When it runs out, and why it does not where it has none. The
		// list carries both and the finding's own screen carried
		// neither, so somebody looking at the one row that matters had
		// to go back to the list to find out when it was due.
		ColumnExpr(`f.due_at AS "due_at"`).
		// A live claim standing at this place, whatever its state. Proposed
		// and waiting counts: it is answered as far as the person looking at
		// it is concerned, and showing it as untouched invites a second claim
		// about the same code.
		//
		// This product's, at the versions shipping here. A place identity
		// carries no product, so without the first a claim in another product
		// that ships the same component reads as standing on this screen; and
		// a live claim is about the versions it was keyed on, so without the
		// second a claim about last release's version answers for this one.
		ColumnExpr(`(SELECT MIN(de.id) FROM "decision" AS "de"
			WHERE de.product_id = ?
			  AND de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND de.live_key IS NOT NULL
			  AND `+KeyMatches+`) AS "decision"`, productID).
		// And which claim that decision is a row of, so that a claim
		// shown on the finding can name the places it covers rather
		// than only count them. At most one live decision stands per
		// combination of code , so this is the same single row the
		// column above reaches.
		ColumnExpr(`(SELECT MIN(de.claim_id) FROM "decision" AS "de"
			WHERE de.product_id = ?
			  AND de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND de.live_key IS NOT NULL
			  AND `+KeyMatches+`) AS "claim"`, productID).
		ColumnExpr(`CASE WHEN f.suppressed_by IS NULL THEN ? ELSE ? END AS "suppressed"`, false, true).
		ColumnExpr(`f.urgency AS "urgency"`).
		ColumnExpr(`f.fix_state AS "fix_state"`).
		ColumnExpr(`f.fixed_in AS "fixed_in"`).
		ColumnExpr(`f.fixed_at AS "fixed_at"`).
		ColumnExpr(`COALESCE(f.matched, '') AS "matched"`).
		ColumnExpr(`COALESCE(f.matched_from, '') AS "matched_from"`).
		ColumnExpr(`COALESCE(f.matched_in, '') AS "matched_in"`).
		ColumnExpr(`COALESCE(f.matched_range, '') AS "matched_range"`).
		ColumnExpr(`COALESCE(f.arrived_from, '') AS "arrived_from"`).
		ColumnExpr(`f.kind AS "kind"`).
		// When this place first appeared here and which run put it
		// there . The run is the provenance of the finding, and it is
		// the only thing that can answer which vulnerability database
		// produced it.
		ColumnExpr(`f.opened_at AS "opened_at"`).
		ColumnExpr(`f.opened_run_id AS "opened_run_id"`).
		Where("f.target_id = ?", targetID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		// The fold rather than the one component named. One judgment covers
		// the whole fold, so the screen a judgment is made from has to show
		// the whole of what it would answer — a form that recorded twelve
		// places having shown six is a form nobody can trust.
		Where(FoldedOn+` = (SELECT c2."fold_key" FROM "component" AS "c2" WHERE c2.id = ?)`,
			componentID).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		OrderExpr("f.urgency DESC, component, consumer").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where this sits: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no open finding is recorded there")
	}

	var issue Vulnerability
	if err := s.db.NewSelect().Model(&issue).Where("id = ?", vulnerabilityID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what this issue is: %w", err)
	}
	// What this product rates it, where somebody here has rated it. The screen
	// is inside one product, so it shows that product's rating and not another
	// team's.
	rated, err := RatingIn(ctx, s.db, productID, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	issue = issue.RatedIn(rated)
	var component graph.Component
	if err := s.db.NewSelect().Model(&component).Where("id = ?", componentID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what this component is: %w", err)
	}

	var aliases []Alias
	if err := s.db.NewSelect().Model(&aliases).
		Where("vulnerability_id = ?", vulnerabilityID).
		Order("identifier").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what else this issue is called: %w", err)
	}
	var references []Reference
	if err := s.db.NewSelect().Model(&references).
		Where("vulnerability_id = ?", vulnerabilityID).
		// Patches first: for somebody deciding whether to backport, the change
		// itself is the answer and everything else is background.
		OrderExpr("CASE WHEN kind = ? THEN 0 ELSE 1 END, url", Patch).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read where this is written up: %w", err)
	}

	var weaknesses []Weakness
	if err := s.db.NewSelect().Model(&weaknesses).
		Where("vulnerability_id = ?", vulnerabilityID).
		Order("cwe").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what kind of flaw this is: %w", err)
	}

	evidence := evidenceFrom(rows, issue, component, aliases, references, weaknesses)

	// When this first appeared here and what produced it. The earliest
	// place, because that is the age the deadline relates to, and the run
	// that opened *that* place is the one that first said this.
	var opened *int64
	for _, row := range rows {
		if evidence.OpenedAt.IsZero() || row.OpenedAt.Before(evidence.OpenedAt) {
			evidence.OpenedAt = row.OpenedAt
			opened = row.OpenedRunID
		}
		// The earliest deadline among the places, because that is the one that
		// makes the whole finding late — the same rule the running-out list
		// and the commitment gate hold.
		if row.DueAt != nil && (evidence.DueAt == nil || row.DueAt.Before(*evidence.DueAt)) {
			evidence.DueAt = row.DueAt
		}
	}
	// Why there is none, where there is none — derived the way the list
	// derives it, because the two reasons are exhaustive: the line is a
	// statement about the rating, and everything else without a deadline
	// is in a release nothing is going to be fixed in. Where both hold it
	// says the line, being the narrower statement about this finding
	// rather than about its release.
	if evidence.DueAt == nil {
		line, err := FloorFor(ctx, s.db, productID)
		if err != nil {
			return nil, err
		}
		evidence.NoDeadline = OutOfSupport
		if !line.Admits(evidence.Exploited, evidence.Severity) {
			evidence.NoDeadline = BelowTheLine
		}
	}
	if opened != nil {
		if evidence.FoundBy, err = s.measured(ctx, *opened); err != nil {
			return nil, err
		}
	}
	// The way down to each place, read in one pass. A place whose consumer is
	// the build itself is asked about by the component, which lands on the
	// same answer with one step in it.
	wanted := make([]int64, 0, 2*len(rows))
	for _, row := range rows {
		wanted = append(wanted, row.ComponentID)
		if row.ConsumerID != nil {
			wanted = append(wanted, *row.ConsumerID)
		}
	}
	chains, err := graph.NewStore(s.db).Chains(ctx, subject, targetID, wanted)
	if err != nil {
		return nil, err
	}
	// The last step of a way down is the package the place is, which now
	// varies within a fold: a chain ending in curl and one ending in
	// libcurl4t64 are two ways to two different packages of one bump.
	shipped, err := s.versionsOf(ctx, wanted)
	if err != nil {
		return nil, err
	}

	evidence.Places = placesOf(rows, chains, shipped)

	// Who is dealing with it. Read here rather than left to a caller, so that
	// the screen somebody reads a finding on is the screen they can hand it
	// over from — being able to record a judgment about something and not to
	// say who is dealing with it is a strange half of the same job.
	//
	// One name for the whole finding, and empty where the places disagree: the
	// assignment is set for a group at once, so a disagreement is a state
	// nobody chose and naming one of them would hide it.
	held, err := s.heldBy(ctx, targetID, vulnerabilityID, componentID)
	if err != nil {
		return nil, err
	}
	evidence.AssignedTo = held
	// And which standing rule put it there, where one did. Read here rather
	// than left to a caller for the same reason the holder is: the screen
	// somebody reads a finding on is where "why is this mine" gets asked.
	placed, err := s.routedBy(ctx, targetID, vulnerabilityID, componentID)
	if err != nil {
		return nil, err
	}
	evidence.RoutedBy = placed
	// The words somebody put on it.
	marks, err := s.TagsOn(ctx, productID, vulnerabilityID, componentID)
	if err != nil {
		return nil, err
	}
	evidence.Tags = marks
	return evidence, nil
}

// heldBy is the sign-in identity of whoever is dealing with a finding, or
// empty where nobody is or the places do not agree.
func (s *Store) heldBy(ctx context.Context, targetID, vulnerabilityID, componentID int64) (string, error) {
	var holders []struct {
		Identity *string `bun:"identity"`
	}
	err := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		// Joined on the party a person is assignable as, which is what
		// the assignment column holds. A team's queue names no person
		// and answers empty here, which is what a queue is.
		Join(`LEFT JOIN "person" AS "p" ON p.party_id = f.assigned_to`).
		ColumnExpr(`p.identity AS "identity"`).
		Where("f.target_id = ?", targetID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.component_id = ?", componentID).
		Where("f.closed_at IS NULL").
		GroupExpr("p.identity").
		Scan(ctx, &holders)
	if err != nil {
		return "", fmt.Errorf("read who is dealing with this: %w", err)
	}
	if len(holders) != 1 || holders[0].Identity == nil {
		return "", nil
	}
	return *holders[0].Identity, nil
}

// routedBy is the name of the rule that placed this finding, or empty where a
// person did or nobody has.
//
// One name for the whole group, and empty where its places disagree: the same
// rule the holder follows, because a group placed two ways is a state nobody
// chose and naming one of them would hide it.
func (s *Store) routedBy(ctx context.Context, targetID, vulnerabilityID,
	componentID int64) (string, error) {

	var named []struct {
		Name *string `bun:"name"`
	}
	err := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`LEFT JOIN "routing_rule" AS "rr" ON rr.id = f.routed_by`).
		ColumnExpr(`rr.name AS "name"`).
		Where("f.target_id = ?", targetID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.component_id = ?", componentID).
		Where("f.closed_at IS NULL").
		GroupExpr("rr.name").
		Scan(ctx, &named)
	if err != nil {
		return "", fmt.Errorf("read what placed this: %w", err)
	}
	if len(named) != 1 || named[0].Name == nil {
		return "", nil
	}
	return *named[0].Name, nil
}

// measured reads what one run was made with.
//
// Nil where the run is gone rather than an error: a finding a person recorded
// has no run at all, and one whose run was pruned is still a finding. What it
// must not do is invent a scanner nobody used.
func (s *Store) measured(ctx context.Context, runID int64) (*Measured, error) {
	var run Run
	if err := s.db.NewSelect().Model(&run).Where("id = ?", runID).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read what produced this: %w", err)
	}
	return &Measured{
		Scanner: run.Scanner, ScannerVersion: run.ScannerVersion,
		DatabaseVersion: run.DatabaseVersion, RanHere: run.RanHere,
		RanAt: run.FinishedAt,
	}, nil
}
