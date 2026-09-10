package database

// PageSize is how many rows a paged read returns, given what was asked for.
//
// Written once because it was written twenty-one times, in six packages, with
// four different ceilings and no rule saying which list gets which. The shape
// is always the same — nothing asked for, or more than the list allows, takes
// the list's own default — and spelling it out at each site is how two lists
// that should agree come to differ by a number nobody chose.
//
// **This is the second statement of the ceiling, not the first.** The API
// declares it on the parameter and refuses anything larger with a message
// naming the bound, which is the answer a caller should get. This one is the
// store defending itself against a caller that is not the API — a background
// pass, a test, a future second surface — and it defaults rather than refusing,
// because a store handed a nonsense page size has nobody to explain it to.
func PageSize(asked, most, byDefault int) int {
	if asked <= 0 || asked > most {
		return byDefault
	}
	return asked
}

// Page is how much of a list a read gives, named rather than spelled.
//
// Six pairs of numbers were in use across twenty-two reads and nothing said
// which list gets which — so a screen could not know what to expect, and two
// lists that should have agreed differed by a number nobody chose. Naming them
// makes the choice a decision somebody made rather than a literal somebody
// typed, and the four kinds below are what the reads actually divide into.
type Page struct {
	// Most is the largest page this kind of read will give, and ByDefault what
	// it gives when nobody says.
	Most, ByDefault int
}

// Of is PageSize for a named page.
func (p Page) Of(asked int) int { return PageSize(asked, p.Most, p.ByDefault) }

var (
	// AList is a list somebody reads on a screen and pages through. Most of
	// them.
	AList = Page{Most: 200, ByDefault: 50}
	// InBulk is a list read to be worked through or written out rather than
	// looked at — an audit trail, an export feeding a spreadsheet, the
	// deferrals somebody is about to review. Bigger, because the cost of a
	// second round trip is paid by a machine.
	InBulk = Page{Most: 500, ByDefault: 100}
	// AWholeBuild is a register: every place in one build with what stands
	// there. It has no natural page, so the default is as large as the
	// interface will render at once.
	AWholeBuild = Page{Most: 500, ByDefault: 200}
	// AComponentsWorth is everything open at one component in one build. A
	// kernel carries thousands, and the whole point of the screen is that
	// somebody decides about them together — so the ceiling is high while the
	// default stays small enough to open quickly.
	AComponentsWorth = Page{Most: 500, ByDefault: 50}
	// APlot is the points on a chart. Small on purpose: a line with two
	// hundred points on it is not a line anybody reads, and the ceiling is
	// what an axis can label.
	APlot = Page{Most: 50, ByDefault: 12}
	// APicker is a list offered to choose from — who to assign to, whose name
	// to complete. Short by intent: a picker showing two hundred names is one
	// nobody reads.
	APicker = Page{Most: 100, ByDefault: 25}
)
