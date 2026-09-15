package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// What is open at one component.
//
// Not the findings list narrowed to one name: this answers per place rather
// than per group, because somebody standing on a component in the dependency
// tree is looking at where it sits.

// AtComponent lists the open issues against one component of a build, with
// every place each one occupies.
//
// Every place, because a decision is keyed on one — so a claim built from a
// single arbitrary place would silence one consumer and leave the others open
// while reporting that it had covered them.
//
// The set somebody narrows before claiming something about all of it. What
// narrows it is theirs — a text match on what a report says is how a candidate
// is found, never why a claim is true.
// It answers with how many findings the whole narrowed set covers as well as
// the page, because it has already counted them: the caller asked for both and
// was running the whole narrowing twice for the second — on a set the store's
// own comment sizes at 222,435 of 272,539 open rows.
func (s *Store) AtComponent(ctx context.Context, subject access.Subject, targetID,
	componentID int64, contains string, limit, offset int) ([]Deciding, int, int, error) {

	return s.atComponent(ctx, subject, targetID, componentID, contains, limit, offset)
}

// SizeAtComponent is how large a claim over the whole narrowed set would be:
// how many issues, and how many findings those sit at.
//
// The second number is the one that matters and the one nothing showed. The
// bound on a bulk action is on rows written rather than on names typed , so a
// screen counting issues against a cap counting findings tells somebody 44
// when the answer is 2,000 — and it tells them after they have typed the
// reasoning.
func (s *Store) SizeAtComponent(ctx context.Context, subject access.Subject, targetID,
	componentID int64, contains string) (issues, places int, err error) {

	_, issues, places, err = s.atComponent(ctx, subject, targetID, componentID, contains, 1, 0)
	return issues, places, err
}

func (s *Store) atComponent(ctx context.Context, subject access.Subject, targetID,
	componentID int64, contains string, limit, offset int) ([]Deciding, int, int, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, 0, 0, err
	}
	visible := access.Visible(subject, productID)
	if !subject.Sees(productID) || len(visible) == 0 {
		return nil, 0, 0, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	limit = database.AComponentsWorth.Of(limit)

	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.TableExpr(`finding AS "f"`).
			Where("f.target_id = ?", targetID).
			Where("f.component_id = ?", componentID).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible))
		if contains != "" {
			// Matched against what a report says, which is all that is held
			// about where a flaw lives. Nothing here knows a kernel from a
			// font library. Asked as a membership test rather than a join so
			// the grouping stays on finding's covering index.
			// Escaped, and the escape character stated. Spliced raw, a term
			// holding a percent or an underscore selected far more issues
			// than the box said — and this is the set a bulk judgment is
			// then recorded against, so one justification landed on issues
			// nobody saw. A backslash matched differently on each engine
			// besides.
			q = q.Where("f.vulnerability_id IN (?)",
				q.NewSelect().TableExpr(`vulnerability AS "v"`).Column("v.id").
					Where(`LOWER(v.description) LIKE ?`+database.LikeClause,
						"%"+containsTerm(contains)+"%"))
		}
		return q
	}

	// The page in two statements, as the findings list is read: which issues,
	// off the covering index, and then what is shown about each. On a real
	// image one component holds most of the build's open rows — the kernel,
	// 222,435 of 272,539 — and grouping them with three joins under the
	// aggregate cost 0.35 s where the index alone answers in 0.04 s. The
	// total rides on the page, as the findings list's does.
	var heads []struct {
		VulnerabilityID int64 `bun:"vulnerability_id"`
		Places          int   `bun:"places"`
		Total           int   `bun:"total"`
	}
	// How many findings the whole narrowed set holds, which is what a bulk
	// action is bounded against and what a screen counting issues
	// cannot say. Counted over the same narrowing rather than summed from the
	// page: a page is fifty of eight hundred.
	reaching, err := narrow(s.db.NewSelect()).ColumnExpr("f.id").Count(ctx)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("count how far these reach: %w", err)
	}
	err = narrow(s.db.NewSelect()).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`COUNT(*) OVER () AS "total"`).
		GroupExpr("f.vulnerability_id").
		OrderExpr("MAX(f.urgency) DESC, f.vulnerability_id").
		Limit(limit).Offset(offset).
		Scan(ctx, &heads)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read what is open against this component: %w", err)
	}
	total := 0
	if len(heads) > 0 {
		total = heads[0].Total
	} else {
		// Grouped and counted, not COUNT DISTINCT: with no GROUP BY, Count()
		// emits its own count(*) and the expression never reaches the
		// statement, so the total counted places while the list counts
		// issues.
		if total, err = s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`, narrow(s.db.NewSelect()).
				ColumnExpr("f.vulnerability_id").GroupExpr("f.vulnerability_id")).
			Count(ctx); err != nil {
			return nil, 0, 0, fmt.Errorf("count what is open against this component: %w", err)
		}
	}
	issues := make([]int64, 0, len(heads))
	for _, head := range heads {
		issues = append(issues, head.VulnerabilityID)
	}

	type shown struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Severity        int    `bun:"severity_centi"`
		FixedIn         string `bun:"fixed_in"`
	}
	about := map[int64]shown{}
	if len(issues) > 0 {
		var rows []shown
		err = s.db.NewSelect().
			TableExpr(`finding AS "f"`).
			Join(`JOIN vulnerability AS "v" ON v.id = f.vulnerability_id`).
			ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
			ColumnExpr(`MIN(COALESCE(v.score_centi, 0)) AS "severity_centi"`).
			ColumnExpr(`MIN(COALESCE(f.fixed_in, '')) AS "fixed_in"`).
			Where("f.target_id = ?", targetID).
			Where("f.component_id = ?", componentID).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible)).
			Where("f.vulnerability_id IN (?)", bun.List(issues)).
			GroupExpr("f.vulnerability_id").
			Scan(ctx, &rows)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("read about what is open against this component: %w", err)
		}
		for _, row := range rows {
			about[row.VulnerabilityID] = row
		}
	}

	// Every place, fetched for the page of issues rather than one arbitrary
	// place per issue. A decision is keyed on a place, so a claim built from
	// MIN(place_identity) covers one consumer and leaves the rest open while
	// reporting that it covered them.
	everywhere, err := s.placesOf(ctx, targetID, componentID, issues, visible)
	if err != nil {
		return nil, 0, 0, err
	}

	at := make([]Deciding, 0, len(heads))
	for _, head := range heads {
		row := about[head.VulnerabilityID]
		for _, place := range everywhere[head.VulnerabilityID] {
			place.ProductID = productID
			place.VulnerabilityID = head.VulnerabilityID
			place.SeverityCenti = row.Severity
			place.FixedIn = row.FixedIn
			place.Places = head.Places
			at = append(at, place)
		}
	}
	return at, total, reaching, nil
}

// placesOf reads every place a set of issues occupies at one component.
func (s *Store) placesOf(ctx context.Context, targetID, componentID int64, issues []int64,
	visible []access.Visibility) (map[int64][]Deciding, error) {

	everywhere := map[int64][]Deciding{}
	if len(issues) == 0 {
		return everywhere, nil
	}
	var rows []struct {
		VulnerabilityID   int64  `bun:"vulnerability_id"`
		PlaceIdentity     string `bun:"place_identity"`
		Visibility        string `bun:"visibility"`
		ComponentUpstream string `bun:"component_upstream"`
		ConsumerUpstream  string `bun:"consumer_upstream"`
	}
	err := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN component AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN component AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`f.visibility AS "visibility"`).
		ColumnExpr(ComponentUpstreamExpr+` AS "component_upstream"`).
		ColumnExpr(ConsumerUpstreamExpr+` AS "consumer_upstream"`).
		Where("f.target_id = ?", targetID).
		Where("f.component_id = ?", componentID).
		Where("f.closed_at IS NULL").
		Where("f.vulnerability_id IN (?)", bun.List(issues)).
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.vulnerability_id, f.place_identity, f.visibility, c.upstream_version, c.version, uc.upstream_version, uc.version").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where these sit: %w", err)
	}
	for _, row := range rows {
		everywhere[row.VulnerabilityID] = append(everywhere[row.VulnerabilityID], Deciding{
			PlaceIdentity:     row.PlaceIdentity,
			Visibility:        access.AsVisibility(row.Visibility),
			ComponentUpstream: row.ComponentUpstream, ConsumerUpstream: row.ConsumerUpstream,
		})
	}
	return everywhere, nil
}

// Candidate is a version a component could go to, and how much reaching it
// would close.
//
// This is the fix-bundle grouping read per component rather than as a list of
// its own: a package at a version, and where it could go.
//
// **Two counts, because they answer different questions.** `FixedHere` is how
// many of what is open name this exact version as their fix, which is that
// release's own security content. `Reached` is how many the upgrade would close
// altogether, counting everything fixed at or before it — which is what
// somebody choosing between two versions is asking, and which needs the
// ecosystem's ordering. Where the ordering is unavailable the two are equal and
// `Ordered` is false, so a list that cannot be ranked is not presented as
// though it were.
type Candidate struct {
	To string
	// FixedHere is what this release fixed: the issues naming this exact
	// version. Sorted on, this reads backwards — a quiet release late on a
	// maintained line names two of its own while carrying every fix before it.
	FixedHere int
	// Reached is everything the upgrade closes, this release and every earlier
	// one. Equal to FixedHere where nothing could be ordered.
	Reached int
	// Ordered says whether Reached means more than FixedHere, which is whether
	// the candidates can be ranked at all.
	Ordered bool
}

// ComponentGroup is one component at one version, with what is open against it
// counted rather than listed.
//
// The level above a findings list. A list of issues answers "what is wrong";
// this answers "where is the weight", which is the question somebody asks
// before deciding what to read and what to put aside. It is also how a person
// finds the one package worth hiding: on a real image the kernel carried 4,943
// of 6,822 rows, and no list of issues makes that visible — it just looks like
// a long list.
type ComponentGroup struct {
	Component string
	Version   string
	// Upstream is what a fork was cut from, carried for the same reason it is
	// carried on a finding: a version nobody recognizes needs it.
	Upstream string
	// UpstreamName is the source package this was built from, where one is
	// recorded. It is what a routing rule matches on, and without it a
	// component row cannot say what a rule about it would have to name — so
	// somebody types the binary package's own name into a field matching
	// source packages and is told, truthfully and uselessly, that nothing is
	// called that.
	UpstreamName string
	// Ecosystem is the kind of package, carried for the same reason a
	// finding's row carries it: a name at a version does not tell two rows
	// apart on its own.
	Ecosystem string
	// BySeverity is those issues by how they were rated, and Worst the
	// highest band among them. Ranking by count alone answers the question
	// this view asks with the opposite of what somebody needs: a package with
	// forty-four issues outranks one with three criticals, and the count
	// beside it says nothing about which.
	BySeverity map[string]int
	Worst      string
	// Issues is how many distinct vulnerabilities are open against it, which
	// is how many rows it contributes to the findings list.
	Issues int
	// Places is how many times those sit somewhere in the build. The two
	// differ by orders of magnitude on shared code and the gap is the point:
	// one kernel issue reaching four hundred modules is one decision.
	Places int
	// Upgrades are the versions upstream has released that would close
	// some of what is open here, each with how many issues it would close.
	//
	// **Listed, never ordered.** Comparing two of these needs an ordering per
	// ecosystem that this does not have, so there is no "nearest"
	// and no "latest" — what there is, is every version the scanner named as
	// carrying a fix, and the count is what makes one of them obviously worth
	// taking. Most components have exactly one.
	Upgrades []Candidate
	// Exploited says whether any of them is known-exploited, which is what
	// stops a component being put aside on the strength of its size alone.
	Exploited bool
	Urgency   int64
}
