// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ErrAmbiguous says a name matched more than one component and no version was
// given to tell them apart.
var ErrAmbiguous = refusal.New("this build contains that name as more than one component")

// ErrNoComponent says a build holds nothing by that name.
//
// A sentinel rather than a sentence, because a name reaching nothing and the
// lookup failing are different answers and a caller that cannot tell them
// apart reports a database fault as a typo, or a typo as a fault.
var ErrNoComponent = refusal.New("this build contains no component by that name")

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
// A part left empty matches anything, with one exception. Where more than one
// matches, the part before the first one left empty was named, and exactly one
// of them has nothing in that part, it is that one: a version named without an
// ecosystem picks the component with no identifier, and an ecosystem named
// without a namespace picks the one with no namespace. A name alone still
// matches every component of that name. The
// choice offered for such a component carries nothing in that part, so
// leaving it out is the only way to name it, and read as "any" that choice
// would lead back to the refusal that offered it.
func Narrowed(which Choice, choices []Choice) []int {
	var kept []int
	for i, choice := range choices {
		if (which.Version == "" || which.Version == choice.Version) &&
			(which.Ecosystem == "" || strings.EqualFold(which.Ecosystem, choice.Ecosystem)) &&
			(which.Namespace == "" || strings.EqualFold(which.Namespace, choice.Namespace)) {
			kept = append(kept, i)
		}
	}
	if len(kept) > 1 && which.Namespace == "" {
		var bare []int
		for _, i := range kept {
			if which.Version != "" && which.Ecosystem == "" && choices[i].Ecosystem == "" ||
				which.Ecosystem != "" && choices[i].Namespace == "" {
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

// Is makes errors.Is(err, ErrAmbiguous) hold for this, so callers that only
// care that it was ambiguous keep working.
func (a *Ambiguous) Is(target error) bool { return target == ErrAmbiguous }

// Refused marks it as a sentence for the caller, who typed the name.
func (a *Ambiguous) Refused() {}

// ComponentAs resolves a component by name and, where they are given, the
// version, ecosystem and namespace a choice names.
//
// The ecosystem and the namespace are needed only because a name and a
// version together are not always unique: a source repository and the package
// built from it share both, and so does one package a producer described under
// two namespaces. An empty part means "any", which is what a caller who has
// never needed it passes.
//
// A name is not unique within a build, and not rarely: a real switch image
// ships three vendored versions of one library. An ambiguous name the choice
// does not narrow is refused rather than resolved to the lowest identifier,
// which answers about a version nobody asked about.
func (s *Store) ComponentAs(ctx context.Context, buildID int64,
	name string, which Choice) (int64, error) {

	return ComponentAsIn(ctx, s.db, buildID, name, which)
}

// ComponentAsIn is ComponentAs over any handle, so a caller that has to
// resolve a component inside its own transaction can rather than reading it
// beforehand and writing against an answer the database has since moved past.
func ComponentAsIn(ctx context.Context, db bun.IDB, buildID int64,
	name string, which Choice) (int64, error) {

	version, ecosystem := which.Version, which.Ecosystem
	// A name somebody types is matched without regard to capitals, through
	// the fold stored beside the component's name and the build's own.
	named, err := NamedAs(ctx, db, name, `"n"."build_id" = ?`, buildID)
	if err != nil {
		return 0, err
	}
	if len(named) == 0 {
		return 0, fmt.Errorf("%w: %q", ErrNoComponent, name)
	}

	query := db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`"c"."id" AS "id"`).
		ColumnExpr(NodeVersion("n", "c")+` AS "version"`).
		ColumnExpr(`"c"."purl" AS "purl"`).
		ColumnExpr(NodeName("n", "c")+` AS "name"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."component_id" IN (?)`, bun.List(named)).
		OrderExpr(`"c"."id"`)
	if version != "" {
		query = query.Where(NodeVersion("n", "c")+` = ?`, version)
	}
	if ecosystem != "" {
		// The ecosystem is escaped and the trailing "/%" is not: the first is
		// a value somebody supplied and the second is the pattern this clause
		// is. Unescaped, "_" matches any character, and one name resolves as
		// another's component.
		query = query.Where(`LOWER("c"."purl") LIKE ?`+database.LikeClause,
			"pkg:"+database.LikeEscaped(strings.ToLower(ecosystem))+"/%")
	}

	var rows []struct {
		ID      int64  `bun:"id"`
		Version string `bun:"version"`
		Purl    string `bun:"purl"`
		Name    string `bun:"name"`
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
	// Two components whose names differ only in capitals are both what a
	// typed name means. The producer's own spelling, which every link
	// carries, names the one spelled that way; any other spelling is
	// answered with the choices.
	if len(rows) > 1 {
		exact := rows[:0:0]
		for _, row := range rows {
			if row.Name == strings.TrimSpace(name) {
				exact = append(exact, row)
			}
		}
		if len(exact) > 0 && len(exact) < len(rows) {
			rows = exact
		}
	}
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
//
// The scheme is compared without regard to capitals and the type is decoded,
// as PartsOfPurl reads them and as the statement narrowing by ecosystem
// compares them. An identifier naming a type and nothing after it still
// answers the type.
func EcosystemOf(purl string) string {
	if ecosystem := PartsOfPurl(purl).Type; ecosystem != "" {
		return ecosystem
	}
	body, _, _ := strings.Cut(strings.TrimSpace(purl), "#")
	body, _, _ = strings.Cut(body, "?")
	scheme, rest, found := strings.Cut(body, ":")
	if !found || !strings.EqualFold(scheme, "pkg") {
		return ""
	}
	ecosystem, _, _ := strings.Cut(strings.Trim(rest, "/"), "/")
	return strings.ToLower(decoded(ecosystem))
}
