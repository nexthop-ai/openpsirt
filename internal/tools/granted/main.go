// Command granted reports a query that asks one grant table and not the other.
//
// A role is held two ways: against one product, and across every product. What
// somebody may do is worked out where those two are resolved together, so every
// check that goes through a subject sees both for free — which is why the roles
// are spread into one map as a subject is built rather than carried as a flag
// into every query.
//
// SQL that names a grant table directly bypasses that. Five such queries missed
// the second kind of grant the day it was added: being handed a finding was
// refused, work was released from somebody who could still open it, the lists of
// who may be mentioned or hold a finding omitted them, and every approval an
// estate approver had given was reported as lapsed. None of them was wrong about
// anything it asked — each simply asked one table.
//
// So the rule is not "do not name a grant table" but "name both". A file
// outside the access package that mentions one and not the other is a predicate
// that cannot see half of what somebody holds, and nothing else in the tree
// notices: it compiles, it passes, and it answers no.
//
// Deliberately crude, like the gates beside it. It reads text rather than
// queries, so a sixth site arrives announced rather than discovered.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// The two tables a role is held in.
const (
	perProduct = "role_grant"
	estate     = "role_grant_all"
)

// allowed is where one may be named alone, and why.
var allowed = []string{
	// The schema, which creates them.
	"internal/database/migrate/",
	// The test harness, which names every table in order to empty them.
	"internal/dbtest/",
	// This program, which names both in order to look for them.
	"internal/tools/granted/",
}

// inside is the access package's own files that may name one alone, and why.
//
// The package was exempt whole, which is where four hand-written copies of the
// union then lived — the one place this gate could not see them. It is checked
// like everything else now, and what names one alone is named here.
var inside = map[string]string{
	// The duplicate-insert check for a grant held across every product. An
	// estate row is what it is about, and a per-product one must not satisfy
	// it: holding a role on one product does not make a grant covering all of
	// them a duplicate.
	"internal/access/estate.go": "the estate duplicate check",
}

func main() {
	var bad []string
	// web holds the interface, which reaches no table: it asks this server.
	read, err := walk.Only(".go", []string{"web"}, func(path string, text []byte) error {
		// A test may assert about one table on purpose: it is saying what is
		// in a row rather than deciding what somebody may reach.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, where := range allowed {
			if strings.HasPrefix(path, where) {
				return nil
			}
		}
		if _, named := inside[path]; named {
			return nil
		}
		// Each table asked about independently, and the answers compared.
		//
		// The rule is "name both", which has two failing shapes and this used
		// to see one. It returned early unless the per-product name appeared,
		// and the estate table's name *contains* the per-product one, so a
		// file naming only the estate table satisfied that test and was then
		// found to name neither once the estate occurrences were taken out.
		// A store query joining the estate table alone cannot see a role held
		// against one product, so it answers no for somebody who holds exactly
		// the grant being asked about — the defect this program describes,
		// with the two tables the other way round.
		body := string(text)
		namesEstate := strings.Contains(body, estate)
		namesPerProduct := strings.Contains(strings.ReplaceAll(body, estate, ""), perProduct)
		if namesPerProduct != namesEstate {
			missing := estate
			if namesEstate {
				missing = perProduct
			}
			bad = append(bad, fmt.Sprintf("%s: names one grant table and not %s", path, missing))
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "granted:", err)
		os.Exit(1)
	}
	if len(bad) > 0 {
		fmt.Fprintln(os.Stderr,
			"these ask one grant table and not the other, so they cannot see a role held\n"+
				"across every product. Ask both, or resolve what somebody holds through a subject:")
		for _, path := range bad {
			fmt.Fprintln(os.Stderr, "  "+path)
		}
		os.Exit(1)
	}
	fmt.Printf("every query asks both grant tables, beside the %d named for asking "+
		"one (%d files checked)\n", len(inside), read)
}
