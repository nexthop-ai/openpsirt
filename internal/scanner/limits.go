package scanner

// Limits bound what one execution of a scanner may produce.
//
// The scanner's report is somebody else's output about somebody else's
// inventory, produced by a process this one starts and reads in the same
// address space the API is served from. Its size is components × matches ×
// references, and the producer controls the first factor by uploading a scan
// file — so nothing about it is bounded by anything this deployment chose
// unless it is bounded here.
//
// The shape is the one `sbom.Limits` has, for the same reason and against the
// same budget: a document being read costs several times what it measures on
// disk, and the chart ships a 512 MiB limit.
type Limits struct {
	// MaxOutput is how many bytes of report a run may produce. Past it the
	// run fails rather than being read in part: half a report is a product
	// that appears to have stopped having problems.
	MaxOutput int64
	// MaxComplaint is how many bytes of a scanner's complaints are kept.
	// Past it the excess is dropped, because a chatty scanner is not a
	// failed run.
	MaxComplaint int64
	// MaxMatches is how many matches a report may state.
	MaxMatches int
	// MaxReferences is how many addresses one match may point at. Bounded
	// separately because the two multiply: a report is matches ×
	// references, and one ceiling cannot size both.
	MaxReferences int
}

// DefaultLimits are the bounds a run uses when given none.
//
// Set from what reading costs rather than from what a report looks like.
//
// A match and a finding are different units and the ceiling is on matches: one
// match becomes as many findings as its component has places in the build, so
// the findings a scan produced are an upper bound on the matches its report
// stated, and usually a loose one. The largest real image measured here
// produced 335,021 findings, so its report stated fewer matches than that —
// which puts a ceiling of half a million above the worst real case by a margin
// nobody has to measure, and still far below what would exhaust the process.
//
// The byte ceiling is the load-bearing one — every other count is bounded by
// it — and it is set the way the inventory reader's is: about half of what the
// chart ships, for one document being read.
func DefaultLimits() Limits {
	return Limits{
		MaxOutput:     256 << 20,
		MaxComplaint:  1 << 20,
		MaxMatches:    500_000,
		MaxReferences: 1_000,
	}
}

// OrDefault fills in anything left unset, so a caller that wants one bound
// changed does not have to restate the rest.
func (l Limits) OrDefault() Limits {
	d := DefaultLimits()
	if l.MaxOutput <= 0 {
		l.MaxOutput = d.MaxOutput
	}
	if l.MaxComplaint <= 0 {
		l.MaxComplaint = d.MaxComplaint
	}
	if l.MaxMatches <= 0 {
		l.MaxMatches = d.MaxMatches
	}
	if l.MaxReferences <= 0 {
		l.MaxReferences = d.MaxReferences
	}
	return l
}
