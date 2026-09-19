package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Routing is a standing rule that hands work nobody holds to a team.
type Routing struct {
	bun.BaseModel `bun:"table:routing_rule,alias:rr"`

	ID        int64 `bun:"id,pk,autoincrement"`
	ProductID int64 `bun:"product_id,notnull"`
	// TeamID is where work lands. A team rather than a person, because
	// what a rule makes is a queue somebody picks out of.
	TeamID int64  `bun:"team_id,notnull"`
	Name   string `bun:"name,notnull"`
	// Ordinal is the whole of the precedence: first match wins, written
	// down rather than implied by insertion order.
	Ordinal int `bun:"ordinal,notnull"`
	// Upstream matches the source package a component was built from, which is
	// the key that matters — one rule naming a source package catches every
	// binary package of it, wherever they sit. Beneath matches a place in the
	// tree. At least one is required.
	Upstream  string     `bun:"upstream"`
	Beneath   string     `bun:"beneath"`
	CreatedBy int64      `bun:"created_by,notnull"`
	CreatedAt time.Time  `bun:"created_at,notnull"`
	RetiredAt *time.Time `bun:"retired_at"`
}

// AddRule records a standing rule and returns it.
//
// The ordinal is assigned here, at the end of the product's list, because
// precedence is a property of the set rather than something a caller invents:
// two rules claiming the same position is a precedence nobody wrote down.
func (s *Store) AddRule(ctx context.Context, by access.Subject, productID, teamID int64,
	name, upstream, beneath string) (*Routing, error) {

	// Asked here rather than only where the request arrives. A rule
	// performs the act the assigner right is named for, continuously, on
	// behalf of whoever wrote it — and a rule written without that right
	// is one nobody can point at afterwards. The handler asks the same
	// question; this is the place a second caller cannot forget to.
	if err := mayRoute(by, productID); err != nil {
		return nil, err
	}
	upstream, beneath = strings.TrimSpace(upstream), strings.TrimSpace(beneath)
	if upstream == "" && beneath == "" {
		return nil, fmt.Errorf("a rule that matches nothing places nothing: " +
			"name a source package, a place in the tree, or both")
	}
	// A rule reaching most of a build is refused when it is written, not left
	// to be discovered by the sweep that runs it every pass. Asked here rather
	// than only at the preview, which is the handler's and which a second
	// caller can forget.
	if beneath != "" {
		if _, err := s.beneathIn(ctx, productID, beneath); err != nil {
			return nil, err
		}
	}
	createdAt := s.now().UTC().Truncate(time.Microsecond)
	var rule *Routing
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		// Built inside, because an insert writes the generated identifier back
		// into the model and the ordinal below is read from the database. A
		// retry of a rolled-back attempt would re-insert a model carrying both
		// of that attempt's answers.
		rule = &Routing{
			ProductID: productID, TeamID: teamID, Name: strings.TrimSpace(name),
			Upstream: strings.ToLower(upstream), Beneath: strings.ToLower(beneath),
			CreatedBy: by.ID, CreatedAt: createdAt,
		}
		// Scanned into a value rather than read through a cursor. A cursor
		// left open on the transaction while the insert runs is two
		// statements interleaved on one connection, which SQLite tolerates
		// and PostgreSQL refuses outright — the four-engine run is what said
		// so, and nothing about the code looked wrong.
		var highest int
		if err := tx.NewSelect().Model((*Routing)(nil)).
			ColumnExpr("COALESCE(MAX(ordinal), 0)").
			Where("product_id = ?", productID).
			Scan(ctx, &highest); err != nil {
			return err
		}
		rule.Ordinal = highest + 1
		_, err := tx.NewInsert().Model(rule).Exec(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("record that rule: %w", err)
	}
	return rule, nil
}

// Rules lists a product's standing rules, in the order they are tried.
func (s *Store) Rules(ctx context.Context, productID int64) ([]Routing, error) {
	var rules []Routing
	if err := s.db.NewSelect().Model(&rules).
		Where("product_id = ?", productID).
		Where("retired_at IS NULL").
		// By identifier as well, because two rules can hold the same
		// ordinal: it is assigned as one past the highest under the
		// engine's ordinary isolation, so two rules created at once
		// take the same number. First match wins is only a rule if the
		// order is the same every time it is asked for.
		Order("ordinal", "id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the rules for this product: %w", err)
	}
	return rules, nil
}

// RetireRule takes a rule out of use. What it already placed stays placed:
// changing a rule never takes something out of somebody's hands, and that
// holds for the team's queue as much as for a person.
func (s *Store) RetireRule(ctx context.Context, by access.Subject, productID, id int64) error {
	if err := mayRoute(by, productID); err != nil {
		return err
	}
	res, err := s.db.NewUpdate().Model((*Routing)(nil)).
		Set("retired_at = ?", s.now().UTC().Truncate(time.Microsecond)).
		Where("id = ?", id).Where("product_id = ?", productID).
		Where("retired_at IS NULL").Exec(ctx)
	if err != nil {
		return fmt.Errorf("retire that rule: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("retire that rule: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("no rule of this product is in use under that identifier")
	}
	return nil
}

// ApplyRules places work nobody holds, one bounded batch at a time.
//
// Only what nobody holds. A human assignment always wins, and
// running a rule never takes something out of somebody's hands — so the write
// matches on a null holder, at the moment of the write, rather than on a set
// read beforehand.
//
// First match wins, which is why the rules are applied in order
// and each one only ever sees what the ones before it left.
//
// Returns how many findings it placed, whether the batch filled, and the rules
// it could not run.
//
// Filling is measured by what was read, not by what was written. The two
// differ: the page is bounded on rows read and the write re-checks the holder,
// so a single assignment landing inside the window makes one row of the batch
// somebody else's. Reading "wrote fewer than the cap" as "reached the end"
// therefore stopped the sweep one human action into a product with fifty
// thousand findings in it, silently, with the job reported successful and the
// rest never routed.
//
// A rule that has outgrown the bound places nothing and stops nothing else.
// It was accepted when it was written and the tree grew under it, which is not
// a fault of the sweep's — and the condition is permanent, so returning it as a
// job failure stopped that product's routing entirely, every rule ordered after
// it included, with a retry that could never clear it. They come back named so
// the caller can say which, because a rule that silently stopped placing is the
// same shape as a rule nobody notices is wrong.
func (s *Store) ApplyRules(ctx context.Context, productID int64, cap int) (int, bool, []int64, error) {
	if cap <= 0 {
		cap = setting.DefaultRoutingBatch
	}
	rules, err := s.Rules(ctx, productID)
	if err != nil {
		return 0, false, nil, err
	}
	if len(rules) == 0 {
		return 0, false, nil, nil
	}
	teams, err := s.partiesOf(ctx, rules)
	if err != nil {
		return 0, false, nil, err
	}

	placed, seen := 0, 0
	var outgrown []int64
	for _, rule := range rules {
		if seen >= cap {
			break
		}
		party, held := teams[rule.TeamID]
		if !held {
			// A rule pointing at a team that has been retired places nothing,
			// rather than placing work where nothing can be picked up from.
			continue
		}
		// The room a rule gets is what the batch has left to read. Handing it
		// what the batch has left to *write* gave the next rule the room the
		// last one lost to a human assignment, which is first-match-wins
		// undone for that batch: work the earlier rule had claimed went to a
		// later one instead.
		read, n, err := s.applyOne(ctx, productID, rule, party, cap-seen)
		if errors.Is(err, ErrTooBroad) {
			outgrown = append(outgrown, rule.ID)
			continue
		}
		if err != nil {
			return placed, false, outgrown, err
		}
		placed += n
		seen += read
	}
	return placed, seen >= cap, outgrown, nil
}

// applyOne is one rule's share of a batch.
func (s *Store) applyOne(ctx context.Context, productID int64, rule Routing,
	party int64, room int) (read, placed int, err error) {

	now := s.now().UTC().Truncate(time.Microsecond)
	// The identifiers to place, read as a bounded page and then written by
	// identifier. Bounded on rows read rather than on rows placed, so a rule
	// matching nothing still spends its budget and the sweep terminates — and
	// the write re-checks the holder so that an assignment landing between the
	// read and the write is not overwritten.
	var ids []int64
	page := s.db.NewSelect().Model((*Finding)(nil)).
		Column("id").
		Where("closed_at IS NULL").
		Where("assigned_to IS NULL").
		Where(inThisProduct, productID).
		Limit(room)
	if rule.Upstream != "" {
		page = bySource(page, rule.Upstream)
	}
	if rule.Beneath != "" {
		// A place in the tree is a walk over one build's edges, and a rule
		// spans a product's builds — so the subtree is resolved per build and
		// the results are unioned. The same walk the tree's own counts use, so
		// a rule and the number beside a node cannot disagree about what is
		// under it.
		beneath, err := s.beneathIn(ctx, productID, rule.Beneath)
		if err != nil {
			return 0, 0, err
		}
		if len(beneath) == 0 {
			return 0, 0, nil
		}
		// Split and OR-ed rather than one list: a subtree is thousands of
		// components, and a statement binding that many parameters is refused
		// by two of the four engines.
		where, args := database.InAnyOf("component_id", beneath)
		page = page.Where(where, args...)
	}
	if err := page.Scan(ctx, &ids); err != nil {
		return 0, 0, fmt.Errorf("read what that rule would place: %w", err)
	}
	if len(ids) == 0 {
		return 0, 0, nil
	}

	res, err := s.db.NewUpdate().Model((*Finding)(nil)).
		Set("assigned_to = ?", party).
		Set("assigned_at = ?", now).
		Set("routed_by = ?", rule.ID).
		Where("id IN (?)", bun.List(ids)).
		// Re-checked at the moment of the write: an assignment that
		// landed between the read and here is somebody's, and a rule
		// never takes something out of anybody's hands.
		Where("assigned_to IS NULL").
		Exec(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("place what that rule matched: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return 0, 0, fmt.Errorf("place what that rule matched: %w", err)
	}
	return len(ids), int(n), nil
}

// bySource narrows to the components a source-package rule names.
//
// The source package is the key that matters: one rule naming it catches every
// binary package built from it, wherever they sit. Falling back to the
// component's own name where no upstream is recorded, so a rule naming
// something that records none still matches it.
//
// One expression, used by the sweep and by the preview, because a preview that
// disagreed with what the rule then does is worse than no preview: it would be
// a confident wrong answer about a thing nobody can otherwise see.
func bySource(query *bun.SelectQuery, pattern string) *bun.SelectQuery {
	// The folded columns, not LOWER() over the raw ones: the four engines fold
	// differently outside ASCII, so asking one to made whether a rule swept a
	// component depend on which engine was running. Folded on the way in, this
	// is an equality test and it can use the index.
	const name = `COALESCE(NULLIF(c.upstream_folded, ''), c.name_folded)`
	if glob, like := globbed(pattern); glob {
		return query.Where(`component_id IN (SELECT c.id FROM "component" AS "c"
			WHERE `+name+` LIKE ?`+database.LikeClause+`)`, like)
	}
	return query.Where(`component_id IN (SELECT c.id FROM "component" AS "c"
		WHERE `+name+` = ?)`, pattern)
}

// globbed says whether a rule's name is a pattern, and what it becomes.
//
// A rule that can only name one package exactly is a rule somebody writes
// forty of: a kernel ships as `linux-image-6.12.41+deb13-sonic-amd64` and
// three more like it, and naming them one at a time is how a rule set stops
// being maintained. So `*` matches any run of characters, and nothing else is
// a metacharacter — a package name is full of dots and plus signs and dashes,
// and a syntax where those mean something is a syntax that surprises.
//
// What SQL treats as special is escaped. `%` and `_` are wildcards to
// LIKE and appear in real package names (`libssl_1_1`), so a pattern that let
// them through would silently match more than it said. The escape character is
// `#` rather than a backslash, because a backslash inside a string literal is
// itself an escape on two of the four engines and `ESCAPE '\'` does not parse
// there at all.
func globbed(name string) (bool, string) {
	if !strings.Contains(name, "*") {
		return false, name
	}
	var like strings.Builder
	for _, r := range name {
		switch r {
		case '*':
			like.WriteByte('%')
		case '%', '_', '#':
			like.WriteByte('#')
			like.WriteRune(r)
		default:
			like.WriteRune(r)
		}
	}
	return true, like.String()
}

// Catches is what a rule would catch, for showing before it is saved.
//
// A rule whose reach nobody can see before saving is a rule that sweeps the
// estate on a guess, and the guess is only found out afterwards — by which
// time thousands of findings are on somebody's queue.
type Catches struct {
	// Components names what it matches, a sample of them, and Total is how
	// many distinct components there are.
	Components []string
	Total      int
	// Work is how many pieces of work sit at those components — one issue in
	// one component, whatever it sits at — and Unheld is how many of those
	// nobody holds. Only the second is what a rule would place, and they are
	// both shown because the gap between them is the thing worth knowing.
	Work, Unheld int
}

// WouldMatch answers what a rule would catch, without recording anything.
//
// It asks exactly what the sweep asks. The two share the predicates rather
// than spelling them twice, because a preview that disagreed with the rule
// would be a confident wrong answer about the one thing nobody can otherwise
// see.
//
// It does not account for the rules already there. First match wins, so
// what this catches is what it would place only where no earlier rule claimed
// it first — which is why the numbers are named for matching rather than for
// placing.
func (s *Store) WouldMatch(ctx context.Context, subject access.Subject,
	productID int64, upstream, beneath string, sample int) (Catches, error) {

	upstream, beneath = strings.ToLower(strings.TrimSpace(upstream)),
		strings.ToLower(strings.TrimSpace(beneath))
	if upstream == "" && beneath == "" {
		return Catches{}, nil
	}
	if sample <= 0 || sample > 100 {
		sample = 20
	}
	// Narrowed to what this subject may read, like every other count and
	// search here. Three numbers and a list of component names are still
	// answers about findings: the gap between what this reports and what the
	// same person's list holds is the size of what they may not see, and a
	// component present only because of an undisclosed finding would be named
	// outright. Somebody who may see nothing here is told nothing rather than
	// zero, since a rule matching nothing and a product holding nothing read
	// alike from outside.
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return Catches{}, nil
	}

	// The same narrowing the sweep does, minus the holder: what a rule matches
	// and what it would place differ by who holds it, and both are worth
	// seeing.
	narrow := func(q *bun.SelectQuery) (*bun.SelectQuery, error) {
		q = q.Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible)).
			Where(inThisProductAs("f.target_id"), productID)
		if upstream != "" {
			q = bySource(q, upstream)
		}
		if beneath != "" {
			under, err := s.beneathIn(ctx, productID, beneath)
			if err != nil {
				return nil, err
			}
			if len(under) == 0 {
				// Nothing is called that, which is a real answer and not an
				// empty one: it is what a typo looks like from here.
				return q.Where("1 = 0"), nil
			}
			where, args := database.InAnyOf("f.component_id", under)
			q = q.Where(where, args...)
		}
		return q, nil
	}

	var found Catches
	names, err := narrow(s.db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "cn" ON cn.id = f.component_id`).
		ColumnExpr(`DISTINCT cn.name AS "name"`).
		OrderExpr("cn.name").
		Limit(sample + 1))
	if err != nil {
		return Catches{}, err
	}
	var shown []string
	if err := names.Scan(ctx, &shown); err != nil {
		return Catches{}, fmt.Errorf("read what that would match: %w", err)
	}
	// Asked for one more than is shown, so "and more" is answerable without a
	// second count over the same rows.
	found.Total = len(shown)
	if len(shown) > sample {
		found.Components = shown[:sample]
	} else {
		found.Components = shown
	}

	counted, err := narrow(s.db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		ColumnExpr("DISTINCT f.vulnerability_id, f.component_id"))
	if err != nil {
		return Catches{}, err
	}
	work, err := s.db.NewSelect().TableExpr(`(?) AS "matched"`, counted).Count(ctx)
	if err != nil {
		return Catches{}, fmt.Errorf("count what that would match: %w", err)
	}
	found.Work = work

	unheld, err := narrow(s.db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		ColumnExpr("DISTINCT f.vulnerability_id, f.component_id").
		Where("f.assigned_to IS NULL"))
	if err != nil {
		return Catches{}, err
	}
	free, err := s.db.NewSelect().TableExpr(`(?) AS "unheld"`, unheld).Count(ctx)
	if err != nil {
		return Catches{}, fmt.Errorf("count what nobody holds: %w", err)
	}
	found.Unheld = free
	return found, nil
}

// beneathIn is every component sitting at or under a named one, across a
// product's builds.
//
// Per build because a walk is over one build's edges, and unioned because a
// rule is about the product. A name the build does not hold contributes
// nothing rather than refusing: a rule naming something one release dropped is
// still a rule about the others.
func (s *Store) beneathIn(ctx context.Context, productID int64, name string) ([]int64, error) {
	var builds []int64
	err := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("tg.id").
		Where("st.product_id = ?", productID).
		Scan(ctx, &builds)
	if err != nil {
		return nil, fmt.Errorf("read which builds this product has: %w", err)
	}

	seen := map[int64]bool{}
	var under []int64
	for _, build := range builds {
		var roots []int64
		if err := s.db.NewSelect().
			TableExpr(`"graph_node" AS "n"`).
			Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
			ColumnExpr("DISTINCT n.component_id").
			Where("n.target_id = ?", build).
			Where("n.closed_scan_id IS NULL").
			Apply(func(q *bun.SelectQuery) *bun.SelectQuery {
				if glob, like := globbed(name); glob {
					return q.Where("c.name_folded LIKE ?"+database.LikeClause, like)
				}
				return q.Where("c.name_folded = ?", name)
			}).
			// One more than the cap, so that reaching it is distinguishable
			// from landing on it exactly. The cap is the store's, not the
			// constant: a store built with a smaller reach truncated at the
			// shipped number and never tripped its own refusal, which is
			// quietly applying to part of what a rule names.
			Limit(s.reaching()+1).
			Scan(ctx, &roots); err != nil {
			return nil, fmt.Errorf("look for that component: %w", err)
		}
		if len(roots) > s.reaching() {
			return nil, fmt.Errorf("%w: %q names more than %d places in one build, which is "+
				"not a place in the tree but most of it — name something narrower",
				ErrTooBroad, name, s.reaching())
		}
		if len(roots) == 0 {
			continue
		}
		// One walk per build rather than one per named component. It was one
		// recursive round trip each, inside a loop over every build of the
		// product, so a pattern matching broadly issued tens of thousands of
		// them in one request.
		var found []int64
		if err := graph.WithinAny(s.db, build, roots).Scan(ctx, &found); err != nil {
			return nil, fmt.Errorf("walk what sits under it: %w", err)
		}
		for _, id := range found {
			if !seen[id] {
				seen[id] = true
				under = append(under, id)
			}
		}
	}
	return under, nil
}

// partiesOf is the assignable name of each rule's team, and omits a team that
// has been retired.
func (s *Store) partiesOf(ctx context.Context, rules []Routing) (map[int64]int64, error) {
	ids := make([]int64, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.TeamID)
	}
	var rows []struct {
		ID      int64 `bun:"id"`
		PartyID int64 `bun:"party_id"`
	}
	err := s.db.NewSelect().
		TableExpr(`"team" AS "tm"`).
		ColumnExpr(`tm.id AS "id"`).
		ColumnExpr(`tm.party_id AS "party_id"`).
		Where("tm.id IN (?)", bun.List(ids)).
		Where("tm.retired_at IS NULL").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which teams these rules point at: %w", err)
	}
	out := make(map[int64]int64, len(rows))
	for _, row := range rows {
		out[row.ID] = row.PartyID
	}
	return out, nil
}

// mayRoute refuses somebody who may not hand work to anybody.
//
// Writing a rule is the assigner right rather than triage: it takes work and
// gives it to a team, over and over, without anybody being present at the
// moment it happens.
func mayRoute(by access.Subject, productID int64) error {
	if by.Kind != access.Person || !by.Holds(access.Assigner, productID) {
		return access.Denied(fmt.Sprintf("hand work to somebody in product %d", productID))
	}
	return nil
}

// reaching is the cap in force for this store.
func (s *Store) reaching() int {
	if s.reach > 0 {
		return s.reach
	}
	return RoutingReach
}

// NewStoreReaching is a store whose rules may name at most this many places in
// one build.
//
// For the test alone, which has to show the refusal without building a fixture
// of two thousand components: what is being checked is that the cap refuses,
// and a slow fixture says the same thing.
func NewStoreReaching(db bun.IDB, reach int) *Store {
	s := NewStore(db)
	s.reach = reach
	return s
}

// RoutingReach is how many places in one build a rule's pattern may name.
//
// A rule says where in the tree something sits, and a pattern matching most of
// a build is not that — a bare `*` matched every open node, and each was a
// recursive walk of its own inside one request. Refused rather than truncated,
// the way a rule matching nothing is refused: a rule quietly applying to part
// of what it names is worse than one nobody could save.
//
// A constant rather than a setting: what counts as an absurdly broad rule is
// not a judgment about a deployment, and the number that is one — how much a
// single pass may place — is already `routing.batch`.
const RoutingReach = 2000

// ErrTooBroad is returned when a rule's pattern names most of a build rather
// than a place in it.
var ErrTooBroad = errors.New("that names too much of the tree")
