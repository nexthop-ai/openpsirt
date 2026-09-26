// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Node is a component's presence in a variant.
//
// The graph is a graph, not a tree. A component reached by several parents is
// one node with several edges, not one node per route. Enumerating routes is a
// separate question, left until real data can say how much a real graph
// shares.
type Node struct {
	bun.BaseModel `bun:"table:graph_node,alias:n"`

	ID           int64  `bun:"id,pk,autoincrement"`
	TargetID     int64  `bun:"target_id,notnull"`
	ComponentID  int64  `bun:"component_id,notnull"`
	IsRoot       bool   `bun:"is_root,notnull"`
	OpenedScanID int64  `bun:"opened_scan_id,notnull"`
	ClosedScanID *int64 `bun:"closed_scan_id"`
}

// Edge is one component depending on another.
type Edge struct {
	bun.BaseModel `bun:"table:graph_edge,alias:e"`

	ID       int64 `bun:"id,pk,autoincrement"`
	TargetID int64 `bun:"target_id,notnull"`
	ParentID int64 `bun:"parent_id,notnull"`
	ChildID  int64 `bun:"child_id,notnull"`
	// Kind is the scope the producer declared for this dependency, in the
	// producer's own word, and empty where it declared none. It is a fact
	// about the document received and nothing reads it to decide anything.
	Kind         string `bun:"kind,notnull"`
	OpenedScanID int64  `bun:"opened_scan_id,notnull"`
	ClosedScanID *int64 `bun:"closed_scan_id"`
}

// Snapshot is the graph a single scan describes.
type Snapshot struct {
	// Components are every component the scan mentions.
	Components []Described
	// Root is the component the scan is about — the product itself. It is
	// marked so it can be excluded from anything that walks upwards: its
	// version changes on every build and its name differs per variant, so
	// letting it into an identity or an expiry rule would invalidate
	// everything below it on every rebuild.
	Root Described
	// Dependencies say which component depends on which, by identity.
	Dependencies []Dependency
}

// Dependency is one edge, named by component identity rather than by row.
type Dependency struct {
	Parent, Child Described
	// Kind is what the producer said this dependency's scope is, in its own
	// word, and empty where it said nothing. Recorded, never acted on.
	Kind string
}

// Applied describes what a snapshot changed.
type Applied struct {
	NodesOpened int
	NodesClosed int
	EdgesOpened int
	EdgesClosed int
}

// Unchanged reports whether the snapshot changed nothing.
func (a Applied) Unchanged() bool {
	return a.NodesOpened == 0 && a.NodesClosed == 0 && a.EdgesOpened == 0 && a.EdgesClosed == 0
}

// Store writes graphs.
type Store struct {
	db         bun.IDB
	components *Components
}

// NewStore returns a graph store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, components: NewComponents(db)}
}

// Apply records a scan's graph against a variant.
//
// Only differences are written. A nightly rebuild that changed nothing writes
// nothing at all — no rows, no history, no growth. That is what keeps the
// stored volume tracking real change rather than the calendar, and it is
// checked by a test rather than assumed.
//
// Everything happens in one transaction: a half-applied graph is
// indistinguishable from components having been removed, which would close
// findings that are still present.
func (s *Store) Apply(ctx context.Context, targetID, scanID int64, snap Snapshot) (Applied, error) {
	var applied Applied
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		applied, err = ApplyWithin(ctx, tx, targetID, scanID, snap)
		return err
	})
	return applied, err
}

// ApplyWithin is the same, inside a transaction the caller opened.
//
// Ingest stores a graph, what the build argued about its own patches and what
// the inventory was made of, and those three are one act: a graph applied
// beside claims that were not recorded reads as a build that withdrew every
// patch it carries, and reopens every finding they suppressed.
func ApplyWithin(ctx context.Context, tx bun.IDB, targetID, scanID int64,
	snap Snapshot) (Applied, error) {

	var applied Applied
	err := func() error {
		// Taken first, before anything is read. Two scans of one target can be
		// in flight at once — the queue hands different jobs to different
		// workers by design — and without this both would read the same open
		// rows, both compute the same difference, and both write it, leaving
		// two open rows where everything downstream assumes one. This is an
		// ordinary row update, so every engine takes the lock and the second
		// worker waits rather than racing.
		if _, err := tx.NewUpdate().Table("target").
			Set("last_scan_id = ?", scanID).
			Where("id = ?", targetID).Exec(ctx); err != nil {
			return fmt.Errorf("take the target: %w", err)
		}

		components := NewComponents(tx)

		// The product itself is stored without the version that moves every
		// build. Everything the document said about it — including every edge
		// hanging off it — has to resolve to that one row, or the version
		// arrives again through the edges and the churn it causes with it.
		root := snap.Root.AsRoot()
		described := snap.Root.Identity()
		asStored := func(d Described) Described {
			if d.Identity() == described {
				return root
			}
			return d
		}

		all := append([]Described{root}, snap.Components...)
		for _, dep := range snap.Dependencies {
			all = append(all, asStored(dep.Parent), asStored(dep.Child))
		}
		ids, err := components.Intern(ctx, all)
		if err != nil {
			return err
		}

		wanted := map[int64]bool{} // component id -> is root
		wanted[ids[root.Identity()]] = true
		for _, d := range snap.Components {
			id := ids[d.Identity()]
			if _, already := wanted[id]; !already {
				wanted[id] = false
			}
		}

		nodeIDs, opened, closed, err := reconcileNodes(ctx, tx, targetID, scanID, wanted)
		if err != nil {
			return err
		}
		applied.NodesOpened, applied.NodesClosed = opened, closed

		wantedEdges := map[edgeAt]bool{}
		for _, dep := range snap.Dependencies {
			parent, okP := nodeIDs[ids[asStored(dep.Parent).Identity()]]
			child, okC := nodeIDs[ids[asStored(dep.Child).Identity()]]
			if !okP || !okC {
				return fmt.Errorf("dependency names a component the snapshot does not list: %s -> %s",
					dep.Parent.Name, dep.Child.Name)
			}
			wantedEdges[edgeAt{Parent: parent, Child: child, Kind: dep.Kind}] = true
		}

		applied.EdgesOpened, applied.EdgesClosed, err = reconcileEdges(ctx, tx, targetID, scanID, wantedEdges)
		return err
	}()
	return applied, err
}

// DB exposes the underlying handle for queries this package does not wrap.
func (s *Store) DB() bun.IDB { return s.db }

// CurrentNodes returns the components present in a variant now.
func (s *Store) CurrentNodes(ctx context.Context, targetID int64) ([]Node, error) {
	var nodes []Node
	err := s.db.NewSelect().Model(&nodes).
		Where("target_id = ?", targetID).
		Where("closed_scan_id IS NULL").
		Scan(ctx)
	return nodes, err
}

// CurrentComponents returns what a target contains now, as the scanner needs
// to be given it.
//
// The scanner is fed from here rather than from the file a build sent, because
// that file is not kept for a moving line: a nightly scan is superseded the
// next night. Re-scanning a year-old release against today's vulnerability
// data works from this, which is why what is not stored can never be scanned.
func (s *Store) CurrentComponents(ctx context.Context, targetID int64) ([]Described, error) {
	var rows []Component
	err := s.db.NewSelect().Model(&rows).
		Join(`JOIN "graph_node" AS "n" ON n.component_id = c.id`).
		Where("n.target_id = ?", targetID).
		Where("n.closed_scan_id IS NULL").
		Where("n.is_root = ?", false).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what a target contains: %w", err)
	}

	described := make([]Described, 0, len(rows))
	for _, row := range rows {
		described = append(described, Described{
			Purl: row.Purl, CPE: row.CPE, Name: row.Name, Version: row.Version,
			UpstreamName: row.UpstreamName, UpstreamVersion: row.UpstreamVersion,
		})
	}
	return described, nil
}

// ComponentAt resolves a component by name within one build.
//
// By name, because that is what a findings list gives out and what somebody
// composing a request has. Scoped to the build so the name means what it means
// there: two products can ship different things under one name, and a lookup
// across everything would answer with whichever was interned first.
func (s *Store) ComponentAt(ctx context.Context, targetID int64, name string) (int64, error) {
	return s.ComponentVersionAt(ctx, targetID, name, "")
}

// ErrAmbiguous says a name matched more than one component and no version was
// given to tell them apart.
var ErrAmbiguous = errors.New("this build contains that name as more than one component")

// ErrNoComponent says a build holds nothing by that name.
//
// A sentinel rather than a sentence, because a name reaching nothing and the
// lookup failing are different answers and a caller that cannot tell them
// apart reports a database fault as a typo, or a typo as a fault.
var ErrNoComponent = errors.New("this build contains no component by that name")

// Ambiguous carries which versions a name matched.
//
// The versions rather than only the fact, because "say which version" is not
// answerable by somebody who does not know what the choices are — and this is
// reached from a link, where whoever followed it has nothing else to go on.
type Ambiguous struct {
	Name string
	// Choices are the ways the name could be meant, each one enough to
	// resolve it. A version alone is not always enough: 13 names in a real
	// image are held at one version by two components — a source repository
	// and the package built from it — so offering only the version hands
	// somebody a choice that leads back to the same refusal.
	Choices []Choice
}

// Choice is one component a name could mean.
//
// The three parts of a package identifier that identity keeps besides the
// name, so that each choice resolves exactly one component: identity drops
// the qualifiers, and what is left to differ is the version, the ecosystem and
// the namespace.
type Choice struct {
	Version   string
	Ecosystem string
	// Namespace tells apart two components one build holds at one version in
	// one ecosystem. A producer describing one Debian package once as the
	// distribution's and once as its own writes two namespaces, and 170 names
	// in one real image arrived that way.
	Namespace string
}

// Narrowed is which of these choices a narrowing names, by position.
//
// A part left empty matches anything, with one exception. An ecosystem named
// without a namespace, where both a component with no namespace and one with a
// namespace match, is the one with none: the choice offered for it carries no
// namespace, so leaving the part out is the only way to name it, and read as
// "any" that choice would lead back to the refusal that offered it.
func Narrowed(which Choice, choices []Choice) []int {
	var kept []int
	for i, choice := range choices {
		if (which.Version == "" || which.Version == choice.Version) &&
			(which.Ecosystem == "" || strings.EqualFold(which.Ecosystem, choice.Ecosystem)) &&
			(which.Namespace == "" || strings.EqualFold(which.Namespace, choice.Namespace)) {
			kept = append(kept, i)
		}
	}
	if len(kept) > 1 && which.Ecosystem != "" && which.Namespace == "" {
		var bare []int
		for _, i := range kept {
			if choices[i].Namespace == "" {
				bare = append(bare, i)
			}
		}
		if len(bare) == 1 {
			return bare
		}
	}
	return kept
}

// ChoiceOf is the choice a component with this identifier and version is.
func ChoiceOf(version, purl string) Choice {
	return Choice{Version: version, Ecosystem: EcosystemOf(purl), Namespace: NamespaceOf(purl)}
}

func (a *Ambiguous) Error() string {
	said := make([]string, 0, len(a.Choices))
	for _, c := range a.Choices {
		kind := c.Ecosystem
		if c.Namespace != "" {
			kind += "/" + c.Namespace
		}
		said = append(said, kind+" "+c.Version)
	}
	return fmt.Sprintf("%s: %q as %s", ErrAmbiguous, a.Name, strings.Join(said, ", "))
}

// Versions are the distinct versions among the choices, in order.
func (a *Ambiguous) Versions() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range a.Choices {
		if !seen[c.Version] {
			seen[c.Version] = true
			out = append(out, c.Version)
		}
	}
	return out
}

// Is makes errors.Is(err, ErrAmbiguous) hold for this, so callers that only
// care that it was ambiguous keep working.
func (a *Ambiguous) Is(target error) bool { return target == ErrAmbiguous }

// ComponentVersionAt resolves a component by name and, where one is given,
// version.
//
// A name is not unique within a build, and not rarely. This was written
// assuming it nearly always was, resolving a collision by taking the lowest
// identifier — stable between requests, which was the property being protected.
// A real switch image then shipped three vendored versions of one library, and
// every one of them resolved to the first: two of the three findings answered
// "no such finding" for a row the list had just drawn, and the third answered
// about a version nobody asked about.
//
// So the version narrows it where the caller has one, and an ambiguous name
// with no version is an error rather than a guess. A caller that guesses on
// behalf of somebody is worse than one that says it cannot tell.
func (s *Store) ComponentVersionAt(ctx context.Context, targetID int64, name, version string) (int64, error) {
	return s.ComponentAs(ctx, targetID, name, Choice{Version: version})
}

// ComponentAs resolves a component by name and, where they are given, the
// version, ecosystem and namespace a choice names.
//
// The ecosystem and the namespace are needed only because a name and a
// version together are not always unique: a source repository and the package
// built from it share both, and so does one package a producer described under
// two namespaces. An empty part means "any", which is what a caller who has
// never needed it passes.
func (s *Store) ComponentAs(ctx context.Context, targetID int64,
	name string, which Choice) (int64, error) {

	return ComponentAsIn(ctx, s.db, targetID, name, which)
}

// ComponentAsIn is ComponentAs over any handle, so a caller that has to
// resolve a component inside its own transaction can rather than reading it
// beforehand and writing against an answer the database has since moved past.
func ComponentAsIn(ctx context.Context, db bun.IDB, targetID int64,
	name string, which Choice) (int64, error) {

	version, ecosystem := which.Version, which.Ecosystem

	query := db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
		ColumnExpr(`c.id AS "id"`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(`c.purl AS "purl"`).
		Where("n.target_id = ?", targetID).
		Where("n.closed_scan_id IS NULL").
		Where("c.name = ?", name).
		OrderExpr("c.id")
	if version != "" {
		query = query.Where("c.version = ?", version)
	}
	if ecosystem != "" {
		// The ecosystem is escaped and the trailing "/%" is not: the first is
		// a value somebody supplied and the second is the pattern this clause
		// is. An unescaped ecosystem made "_" match any character, so one
		// name could be resolved as another's component.
		query = query.Where("LOWER(c.purl) LIKE ?"+database.LikeClause,
			"pkg:"+database.LikeEscaped(strings.ToLower(ecosystem))+"/%")
	}

	var rows []struct {
		ID      int64  `bun:"id"`
		Version string `bun:"version"`
		Purl    string `bun:"purl"`
	}
	if err := query.Scan(ctx, &rows); err != nil {
		return 0, fmt.Errorf("look up component %q: %w", name, err)
	}
	// Narrowed here rather than in the statement. A namespace can run to
	// several segments and carries escapes, so a pattern over the stored
	// identifier matches it only approximately, and the rows left by this point
	// are the few components sharing one name.
	found := make([]Choice, len(rows))
	for i, row := range rows {
		found[i] = ChoiceOf(row.Version, row.Purl)
	}
	kept := rows[:0]
	for _, i := range Narrowed(which, found) {
		kept = append(kept, rows[i])
	}
	rows = kept
	if len(rows) == 0 {
		return 0, fmt.Errorf("%w: %q", ErrNoComponent, name)
	}
	if len(rows) > 1 {
		choices := make([]Choice, 0, len(rows))
		for _, row := range rows {
			choices = append(choices, ChoiceOf(row.Version, row.Purl))
		}
		return 0, &Ambiguous{Name: name, Choices: choices}
	}
	return rows[0].ID, nil
}

// NamespaceOf reads the namespace out of a package identifier, decoded, and
// empty where the identifier has none.
func NamespaceOf(purl string) string {
	return PartsOfPurl(purl).Namespace
}

// EcosystemOf reads the ecosystem out of a package identifier, which with the
// namespace is what tells two components with one name and one version apart.
func EcosystemOf(purl string) string {
	rest, found := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !found {
		return ""
	}
	ecosystem, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(ecosystem)
}

// Neighbor is one component next to another in the graph.
type Neighbor struct {
	Name    string `bun:"name"`
	Version string `bun:"version"`
	// Findings is how many distinct issues are open against this component
	// itself, and Beneath is that over it and everything under it.
	//
	// Both, because they answer different questions and a container answers
	// zero to the first: it holds no findings of its own, so a tree showing
	// only that says every container is clean while the packages inside them
	// hold thousands. What makes a branch worth opening is what is in it.
	//
	// Issues rather than finding rows. A finding is one issue at one place,
	// and the issues open against a component are the same at every place it
	// sits — so a node drawn beneath one parent is looking at one place, and
	// the count is the issues there, not the rows across every place.
	Findings int `bun:"findings"`
	Beneath  int `bun:"beneath,scanonly"`
	// BeneathBy is that same number by how the issues were rated. A node
	// saying five thousand beneath it says nothing about whether any of it
	// matters, which is exactly what somebody deciding where to descend is
	// asking. The bands sum to Beneath, because an issue has one rating.
	BeneathBy map[string]int `bun:"-"`
	Children  int            `bun:"children"`
	// Purl is the package identifier, which is where the kind of package it is
	// comes from.
	//
	// The field that tells two components of one name and one version apart. A
	// build ships `opennsl-modules` twice at 15.2.0.0.0.0.0.0, and asking
	// about either by name is refused — rightly, since they are two components
	// — so a screen listing them without this could name neither. The refusal
	// even says which field to send, and nothing offering the choice was
	// saying it.
	//
	// Carried as the identifier rather than as the word, and turned into the
	// word by the one function that knows how, where every other reader of a
	// component does the same.
	Purl string `bun:"purl,scanonly"`
	// ComponentID is what the rollup is worked out from. Read rather than
	// shown.
	ComponentID int64 `bun:"component_id"`
}

// Around reports what sits directly above and below one component in a build.
//
// A neighborhood rather than a tree. Eight thousand components will not draw
// and would not be readable if they did, so what is asked for is one step at a
// time — and the counts come with it, because descending a graph without them
// is exploring rather than following anything.
//
// Naming a component rather than an identifier: it is what a findings list
// gives out and what somebody composing a request has.
// The choice says which component, where the build ships the name as more
// than one: a name alone is refused as ambiguous, naming the choices, the way
// a finding is.
func (s *Store) Around(ctx context.Context, subject access.Subject, targetID int64,
	name string, which Choice) ([]Neighbor, []Neighbor, error) {

	// Authorized before the name is resolved, which is what the two siblings
	// here already do. The other way round a refusal was informative: a name
	// the build does not hold answered 404, a name it holds twice answered 409
	// naming every version and ecosystem, and a name it holds once answered
	// 403 — so a subject who may not read findings here could read the
	// build's inventory back one name at a time.
	productID, readable, err := s.visibleIn(ctx, subject, targetID)
	if err != nil {
		return nil, nil, err
	}
	componentID, err := s.ComponentAs(ctx, targetID, name, which)
	if err != nil {
		return nil, nil, err
	}
	below, err := s.step(ctx, readable, targetID, componentID, true)
	if err != nil {
		return nil, nil, err
	}
	above, err := s.step(ctx, readable, targetID, componentID, false)
	if err != nil {
		return nil, nil, err
	}
	// Everything beneath each neighbor, both directions in one statement.
	if err := s.filled(ctx, productID, targetID, readable, above, below); err != nil {
		return nil, nil, err
	}
	// Ordered after that, not before: what a branch is ranked on is what is
	// beneath it, which nothing knows until here.
	ordered(above)
	ordered(below)
	return above, below, nil
}

// filled writes what is open beneath each of these rows, in one statement
// for all of them however many lists they arrive in.
//
// The contents of each of them, not only what is on it. A container holds no
// findings of its own, so without this every one of them reads zero while
// the packages inside hold thousands — and a tree whose counts cannot tell a
// full branch from an empty one is not something anybody can descend by.
func (s *Store) filled(ctx context.Context, productID, targetID int64,
	readable []access.Visibility, lists ...[]Neighbor) error {

	return s.filledWith(ctx, productID, targetID, readable, adoption{}, lists...)
}

// filledWith is filled with an adoption: the adopter's number covers what it
// adopts as well as what is under it.
func (s *Store) filledWith(ctx context.Context, productID, targetID int64,
	readable []access.Visibility, adopt adoption, lists ...[]Neighbor) error {

	var ids []int64
	for _, rows := range lists {
		for _, row := range rows {
			ids = append(ids, row.ComponentID)
		}
	}
	totals, err := s.beneath(ctx, productID, targetID, readable, ids, adopt)
	if err != nil {
		return err
	}
	for _, rows := range lists {
		for i := range rows {
			bands := totals[rows[i].ComponentID]
			rows[i].BeneathBy = bands
			// Summed from the parts rather than counted twice: an issue has
			// one rating, so the bands partition the distinct issues and the
			// two numbers cannot disagree.
			rows[i].Beneath = 0
			for _, n := range bands {
				rows[i].Beneath += n
			}
		}
	}
	return nil
}

// Roots reports the build's own component and what it pulls in directly.
//
// The root comes back with its children because a tree drawn without it is
// drawn without the thing being explored: every path shown starts one step in,
// and the indentation has nothing to hang from. It is nil where nothing has
// been applied to the build.
//
// What the root pulls in directly includes every component nothing else in
// the build pulls in. The build contains them, and with nothing above them the
// build is what holds them.
func (s *Store) Roots(ctx context.Context, subject access.Subject, targetID int64) (
	*Neighbor, []Neighbor, error) {

	productID, readable, err := s.visibleIn(ctx, subject, targetID)
	if err != nil {
		return nil, nil, err
	}
	var rootID int64
	err = s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		ColumnExpr("n.component_id").
		Where("n.target_id = ?", targetID).
		Where("n.closed_scan_id IS NULL").
		Where("n.is_root = ?", true).
		Limit(1).Scan(ctx, &rootID)
	if database.IsNoRows(err) {
		// Nothing has been applied to this build: every graph applied has a
		// root, because a snapshot without one is refused.
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("look up what this build is: %w", err)
	}
	loose, err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "fn"`).
		Where("fn.target_id = ?", targetID).
		Where("fn.closed_scan_id IS NULL").
		Where("fn.is_root = ?", false).
		Where(orphaned).
		Exists(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("ask whether anything in the build hangs from nothing: %w", err)
	}

	var kids []Neighbor
	if !loose {
		kids, err = s.step(ctx, readable, targetID, rootID, true)
	} else {
		kids, err = s.topLevel(ctx, readable, targetID)
	}
	if err != nil {
		return nil, nil, err
	}
	root, err := s.describe(ctx, readable, targetID, rootID, len(kids))
	if err != nil {
		return nil, nil, err
	}
	if root == nil {
		// A document that named no root of its own. The children are still
		// what somebody reads, so they are still filled in and ordered — the
		// list is the screen either way.
		if err := s.filled(ctx, productID, targetID, readable, kids); err != nil {
			return nil, nil, err
		}
		ordered(kids)
		return nil, kids, nil
	}
	// The root and its children counted in the one statement. The root's own
	// number is the whole build's, and it was a second walk of the same edges
	// when asked for on its own. What nothing pulls in is adopted by the root:
	// no edge joins the two, so walking from the root alone reads zero above
	// children that hold thousands.
	var adopt adoption
	if loose {
		// The rows the root holds directly, rather than the orphans alone:
		// the list does not say which is which, and walking a child of the
		// root from the root as well reaches nothing it would not reach.
		adopt.By = rootID
		for _, row := range kids {
			adopt.IDs = append(adopt.IDs, row.ComponentID)
		}
	}
	top := []Neighbor{*root}
	if err := s.filledWith(ctx, productID, targetID, readable, adopt, top, kids); err != nil {
		return nil, nil, err
	}
	root.Beneath = top[0].Beneath
	root.BeneathBy = top[0].BeneathBy
	ordered(kids)
	return root, kids, nil
}

// describe reads one component as a neighbor of nothing, for the root.
//
// The child count is passed in rather than counted again: the caller has just
// walked that edge and holds the answer, and asking the database a second time
// for a number already in hand is how the same walk ends up costing twice.
func (s *Store) describe(ctx context.Context, readable []access.Visibility, targetID, componentID int64,
	children int) (*Neighbor, error) {

	row := &Neighbor{Children: children, ComponentID: componentID}
	err := s.db.NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`c.name AS "name"`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(`c.purl AS "purl"`).
		// Narrowed exactly as the neighbors are. The root is one row, but a
		// count that is not narrowed the same way is still a count of what the
		// reader may not see.
		ColumnExpr(`(SELECT COUNT(DISTINCT f.vulnerability_id) FROM "finding" AS "f"
			WHERE f.target_id = ? AND f.component_id = c.id
			  AND f.closed_at IS NULL AND f.visibility IN (?)) AS "findings"`,
			targetID, bun.List(readable)).
		Where("c.id = ?", componentID).
		Scan(ctx, row)
	if database.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read what this build is: %w", err)
	}
	return row, nil
}

// step walks one edge, downward or upward.
//
// Edges join *nodes* rather than components — a node is a component's presence
// in one build — so both ends go through the node table. Reading the edge
// columns as component identifiers is the mistake this comment exists to stop
// somebody making twice.
func (s *Store) step(ctx context.Context, readable []access.Visibility, targetID, componentID int64,
	down bool) ([]Neighbor, error) {
	near, far := "parent_id", "child_id"
	if !down {
		near, far = far, near
	}

	var rows []Neighbor
	query := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "nn" ON nn.id = e.` + near).
		Join(`JOIN "graph_node" AS "fn" ON fn.id = e.` + far)
	err := neighborsAt(query, readable, targetID).
		Where("e.target_id = ?", targetID).
		Where("nn.component_id = ?", componentID).
		Where("e.closed_scan_id IS NULL").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("walk the graph: %w", err)
	}

	// Ordered by ordered(), after the caller has filled in what is beneath
	// each — the number a branch is ranked on is not known until then.
	return rows, nil
}

// neighborsAt reads each node the query reaches as "fn" as a neighbor: its
// component, what is open against it and how many things it pulls in, in the
// order a reader descends by.
func neighborsAt(query *bun.SelectQuery, readable []access.Visibility,
	targetID int64) *bun.SelectQuery {

	return query.
		Join(`JOIN "component" AS "c" ON c.id = fn.component_id`).
		Join(`LEFT JOIN (SELECT dp.component_id AS "cid", COUNT(*) AS "n"
			FROM "graph_edge" AS "d"
			JOIN "graph_node" AS "dp" ON dp.id = d.parent_id
			WHERE d.target_id = ? AND d.closed_scan_id IS NULL
			GROUP BY dp.component_id) AS "kids" ON kids.cid = c.id`, targetID).
		ColumnExpr(`c.id AS "component_id"`).
		ColumnExpr(`c.name AS "name"`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(`c.purl AS "purl"`).
		// Everything open against it here, so descending follows the findings
		// rather than being exploration. Narrowed like every other count.
		// Without this a reader browsing the tree gets an accurate count of
		// the undisclosed findings under each component and can bisect down to
		// which one holds them — a leak that needs no row to be shown.
		//
		// Counted once for the build and joined, like the children below,
		// rather than asked per row. As a correlated subquery this had two
		// indexes to choose from once the findings list's covering index
		// existed — the target and the component, or the target, open and
		// visibility — and SQLite without statistics took the second, which
		// matches every open row in the build, once per child: 0.30 s for
		// the root's thirty children against 0.09 s as one grouped pass.
		Join(`LEFT JOIN (SELECT f.component_id AS "cid", COUNT(DISTINCT f.vulnerability_id) AS "n"
			FROM "finding" AS "f"
			WHERE f.target_id = ? AND f.closed_at IS NULL AND f.visibility IN (?)
			GROUP BY f.component_id) AS "open" ON open.cid = c.id`, targetID, bun.List(readable)).
		ColumnExpr(`COALESCE(open.n, 0) AS "findings"`).
		// Anything under it, so a node that opens can be told from
		// one that does not before somebody clicks it.
		//
		// Counted once for the whole build and joined, rather than asked per
		// row. As a correlated subquery this has no index to take: it is bound
		// on the child's component, while the only way into the edge table is
		// the target, so each row scanned every edge in the build. Measured on
		// a switch operating-system image — 19,192 edges, 5,270 components
		// directly under the root — that column alone cost 5.06 s against
		// 0.106 s for one pass. An index on the node's component was tried
		// first and made it worse (5.4 s to 10.0 s), because the scan being
		// repeated is over the edges rather than the lookup it drives.
		ColumnExpr(`COALESCE(kids.n, 0) AS "children"`).
		// kids.n and open.n are grouped on as well as selected. Each is one
		// value per c.id and so adds nothing, but the engines that enforce
		// the rule strictly will not take a column from a joined subquery on
		// the strength of a primary key belonging to a different table.
		GroupExpr("c.id, c.name, c.version, kids.n, open.n").
		// Anything that opens comes before anything that does not, and within
		// each the most findings first.
		//
		// Ordering by findings alone buries the structure: a container holds
		// no findings of its own, so on a real image the root's 5,270
		// children put the first thing that opens at position 546 and every
		// one of the 37 containers below that. A tree whose first screen
		// contains no branches is a list, and the reader never learns the
		// build has containers in it at all.
		OrderExpr("CASE WHEN COALESCE(kids.n, 0) > 0 THEN 0 ELSE 1 END, findings DESC, c.name")
}

// orphaned is the condition that nothing in the build pulls in the node the
// query reaches as "fn".
//
// Asked by the node alone. A node belongs to one build, so naming the build as
// well adds nothing, and it steers SQLite onto the index led by the build,
// where the child is the fourth column: every open edge in the build scanned
// once per node, 7.28 s for 59,982 nodes against 45 ms on the index led by the
// child.
const orphaned = `NOT EXISTS (SELECT 1 FROM "graph_edge" AS "pe"
	WHERE pe.child_id = fn.id AND pe.closed_scan_id IS NULL)`

// topLevel reads what the root pulls in and what nothing pulls in, as one
// list in one statement: the two are read with the same per-build counts, and
// read apart each pays for them.
//
// A document that states no edge from its root still lists what the build
// contains, and a component with no parent is contained by nothing else. One
// real switch image arrived with 60,935 components, 1,358 edges and none of
// them from the root, and drawn from the root alone its tree was empty.
func (s *Store) topLevel(ctx context.Context, readable []access.Visibility,
	targetID int64) ([]Neighbor, error) {

	var rows []Neighbor
	err := neighborsAt(s.db.NewSelect().TableExpr(`"graph_node" AS "fn"`), readable, targetID).
		Where("fn.target_id = ?", targetID).
		Where("fn.closed_scan_id IS NULL").
		Where("fn.is_root = ?", false).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where(orphaned).
				WhereOr(`EXISTS (SELECT 1 FROM "graph_edge" AS "re"
					JOIN "graph_node" AS "rn" ON rn.id = re.parent_id
					WHERE re.child_id = fn.id AND re.closed_scan_id IS NULL AND rn.is_root = ?)`, true)
		}).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what the build holds directly: %w", err)
	}
	return rows, nil
}

// ordered puts a list of neighbors in the order somebody reads it: what opens
// first, and within each group the most findings first.
//
// The number a row is ranked on is the number that describes it: for a
// branch, everything open beneath it, and for a leaf, its own count — which
// for a leaf are the same number anyway. A container holds nothing of its own,
// so ranking it on that put every container at zero and the list fell back to
// alphabetical, which is what it looked like.
//
// A node that opens still comes before one that does not. A container holds no
// findings of its own, and on a real image the root's 5,270 children put the
// first thing that opens at position 546 when structure was not held above
// contents. A tree whose first screen contains no branches is a list, and the
// reader never learns the build has containers in it.
//
// The cost, stated because it was the reason branches were ordered by name
// before: an edge here means "contains or depends on" and the document does
// not distinguish the two, so forty kernel-module packages each depending on
// the one kernel each report the kernel's findings beneath them. Deep in a
// tree that groups them together at the top. Ranking by name instead avoided
// that and produced a worse problem everywhere else — an alphabetical list of
// containers, which is what the ordering exists to prevent.
func ordered(rows []Neighbor) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if (a.Children > 0) != (b.Children > 0) {
			return a.Children > 0
		}
		if ranks(a) != ranks(b) {
			return ranks(a) > ranks(b)
		}
		return a.Name < b.Name
	})
}

// ranks is what a row is ordered on: everything open beneath it, which for a
// leaf is its own count.
func ranks(n Neighbor) int {
	if n.Beneath > n.Findings {
		return n.Beneath
	}
	return n.Findings
}

// knowsBuild refuses somebody who may not know this build exists.
//
// The weaker of the two questions here, and the right one for a read that
// carries no findings: the way down to a component is the build's shape rather
// than what is open against it. It admits a case collaborator, which is the
// same rule the catalog's own lookup applies — the names their issue sits at
// have to resolve, and so does the path to the component it sits in, or the
// grant shows them a row they cannot open.
//
// visibleIn is the other question and stays where counts are answered. A count
// of findings narrowed by a case grant would be a count of the product's work,
// and that is what a collaborator may not have.
func (s *Store) knowsBuild(ctx context.Context, subject access.Subject, targetID int64) error {
	productID, err := catalog.NewStore(s.db).ProductOf(ctx, targetID)
	if err != nil {
		return err
	}
	if !subject.Sees(productID) && len(subject.Cases(productID)) == 0 {
		return access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	return nil
}

// visibleIn reports the visibilities this subject may read in a build, and
// refuses where they may read none.
//
// The graph is browsed beside a findings list that is narrowed correctly, so a
// count here that is not narrowed the same way is the more dangerous of the
// two: nobody looking at it expects it to be a disclosure.
func (s *Store) visibleIn(ctx context.Context, subject access.Subject, targetID int64) (int64, []access.Visibility, error) {
	productID, err := catalog.NewStore(s.db).ProductOf(ctx, targetID)
	if err != nil {
		return 0, nil, err
	}
	if !subject.Sees(productID) {
		return 0, nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	readable := []access.Visibility{}
	if subject.Reads(access.Public, productID) {
		readable = append(readable, access.Public)
	}
	if subject.Reads(access.Private, productID) {
		readable = append(readable, access.Private)
	}
	if len(readable) == 0 {
		return 0, nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	// The product comes back with what may be read in it, because the rating
	// a band is drawn from belongs to that same product: a count severity-
	// banded for one product while authorized against another is the fault
	// this pair exists to make unspellable.
	return productID, readable, nil
}

// Step is one component on the way down to another.
type Step struct {
	Name    string
	Version string
	// Purl is the step's package identifier, which its ecosystem and
	// namespace are read out of: the tree names a row by all four.
	Purl string
}

// Counts reports how much the build's graph holds, which is what the screen
// showing it says at the top.
//
// Two numbers rather than one because they answer different questions: how
// much was inventoried, and how much of it was placed. A build with many
// components and few edges is a document that listed everything and said
// where almost nothing went.
func (s *Store) Counts(ctx context.Context, subject access.Subject, targetID int64) (Tally, error) {
	if _, _, err := s.visibleIn(ctx, subject, targetID); err != nil {
		return Tally{}, err
	}
	components, err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Where("n.target_id = ?", targetID).
		Where("n.closed_scan_id IS NULL").
		// The build's own root is not one of its components, which is what the
		// list beside this number already says. Counted, the header read one
		// higher than the rows below it on every build.
		Where("n.is_root = ?", false).
		Count(ctx)
	if err != nil {
		return Tally{}, fmt.Errorf("count what this build holds: %w", err)
	}
	edges, err := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Where("e.target_id = ?", targetID).
		Where("e.closed_scan_id IS NULL").
		Count(ctx)
	if err != nil {
		return Tally{}, fmt.Errorf("count what this build's edges are: %w", err)
	}
	// The components carrying neither a package identifier nor a platform
	// enumeration, which is everything a scanner matches on. They ship and are
	// tracked, and no scan can say anything about them, so a build of nothing
	// else reports no findings and reads as clean.
	unidentified, err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
		Where("n.target_id = ?", targetID).
		Where("n.closed_scan_id IS NULL").
		Where("n.is_root = ?", false).
		Where("(c.purl IS NULL OR c.purl = '')").
		Where("(c.cpe IS NULL OR c.cpe = '')").
		Count(ctx)
	if err != nil {
		return Tally{}, fmt.Errorf("count what this build holds that nothing can match: %w", err)
	}
	return Tally{Components: components, Edges: edges, Unidentified: unidentified}, nil
}

// Tally is how much a build's graph holds.
type Tally struct {
	Components int
	Edges      int
	// Unidentified is how many of the components carry nothing a scanner can
	// match them on.
	Unidentified int
}

// Search finds components of a build by name.
//
// Opening nodes does not find anything in a graph this size — eight thousand
// components under a root with five thousand children — so searching is the
// way in and browsing is for answering "what else is under this" once somebody
// is already somewhere. A tree without it is a tree nobody reaches the middle
// of.
//
// Matched on a substring of the name, case-folded, because somebody looking
// for openssl types "ssl" and should not have to know whether the package is
// called openssl, libssl3t64 or symcrypt-openssl. Ordered by findings so the
// first answer is the one worth opening.
func (s *Store) Search(ctx context.Context, subject access.Subject, targetID int64,
	term string, limit int) ([]Neighbor, error) {

	_, readable, err := s.visibleIn(ctx, subject, targetID)
	if err != nil {
		return nil, err
	}
	term = strings.TrimSpace(term)
	if term == "" {
		return nil, nil
	}
	limit = database.AList.Of(limit)

	// The components matched, each once however many places it sits at. The
	// name is matched on its folded form, which is lowercased and trimmed
	// when stored, so no engine is asked to compare loosely; and the term is
	// escaped as well as folded, so a term of "%" searches for a percent sign.
	matched := `(SELECT DISTINCT n.component_id AS "cid"
		FROM "graph_node" AS "n"
		JOIN "component" AS "m" ON m.id = n.component_id
		WHERE n.target_id = ? AND n.closed_scan_id IS NULL
		  AND m.name_folded LIKE ?` + database.LikeClause + `) AS "matched"`

	var rows []Neighbor
	err = s.db.NewSelect().
		TableExpr(matched, targetID, "%"+database.LikeEscaped(Folded(term))+"%").
		Join(`JOIN "component" AS "c" ON c.id = matched.cid`).
		// Issues rather than finding rows, which is what this field is and
		// what the two queries that browse to the same component answer: a
		// library reachable under three parents is one issue, not three.
		//
		// Counted in one grouped pass over the build's open findings, which
		// the covering index over target, closure, visibility, issue and
		// component answers without reading a row. Counted per matched
		// component instead, SQLite reads the whole build's open findings once
		// per component through the same index, and a term matching many
		// names takes most of a minute: 17.1 s for "li" on a switch image of
		// 297,881 open findings, where this takes 0.24 s.
		Join(`LEFT JOIN (SELECT f.component_id AS "cid",
				COUNT(DISTINCT f.vulnerability_id) AS "n"
			FROM "finding" AS "f"
			WHERE f.target_id = ? AND f.closed_at IS NULL AND f.visibility IN (?)
			GROUP BY f.component_id) AS "counted" ON counted.cid = c.id`,
			targetID, bun.List(readable)).
		Join(`LEFT JOIN (SELECT dp.component_id AS "cid", COUNT(*) AS "n"
			FROM "graph_edge" AS "d"
			JOIN "graph_node" AS "dp" ON dp.id = d.parent_id
			WHERE d.target_id = ? AND d.closed_scan_id IS NULL
			GROUP BY dp.component_id) AS "kids" ON kids.cid = c.id`, targetID).
		ColumnExpr(`c.name AS "name"`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(`c.purl AS "purl"`).
		ColumnExpr(`COALESCE(counted.n, 0) AS "findings"`).
		ColumnExpr(`COALESCE(kids.n, 0) AS "children"`).
		OrderExpr(`"findings" DESC, c.name`).
		Limit(limit).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("search the build: %w", err)
	}
	return rows, nil
}

// DeclaredScopes is what a producer said about each edge arriving at one
// component in one build, by the component that pulls it in.
//
// Keyed on the puller rather than on the edge row, because that is what a place
// names: a finding sits at a component under a consumer, and the product itself
// is a consumer of nothing, which is the zero key here for the same reason a
// place under the build carries no consumer.
//
// A word is present only where the producer stated one, and most inventories
// state none at all.
func (s *Store) DeclaredScopes(ctx context.Context, targetID int64,
	componentIDs []int64) (map[[2]int64]string, error) {

	if len(componentIDs) == 0 {
		return map[[2]int64]string{}, nil
	}
	var rows []struct {
		ChildComponentID  int64  `bun:"child_component_id"`
		ParentComponentID int64  `bun:"parent_component_id"`
		ParentIsRoot      bool   `bun:"parent_is_root"`
		Kind              string `bun:"kind"`
	}
	err := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "child" ON child.id = e.child_id`).
		Join(`JOIN "graph_node" AS "parent" ON parent.id = e.parent_id`).
		ColumnExpr(`child.component_id AS "child_component_id"`).
		ColumnExpr(`parent.component_id AS "parent_component_id"`).
		ColumnExpr(`parent.is_root AS "parent_is_root"`).
		ColumnExpr(`e.kind AS "kind"`).
		Where("e.target_id = ?", targetID).
		Where("e.closed_scan_id IS NULL").
		Where("e.kind <> ?", "").
		Where("child.component_id IN (?)", bun.List(componentIDs)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what the producer called these dependencies: %w", err)
	}
	scopes := make(map[[2]int64]string, len(rows))
	for _, row := range rows {
		puller := row.ParentComponentID
		if row.ParentIsRoot {
			puller = 0
		}
		at := [2]int64{row.ChildComponentID, puller}
		// The first stated word for a pair. A component reached from one
		// consumer by two edges is one place, and two words for it is the
		// producer having said two things about the same dependency.
		if _, already := scopes[at]; !already {
			scopes[at] = row.Kind
		}
	}
	return scopes, nil
}
