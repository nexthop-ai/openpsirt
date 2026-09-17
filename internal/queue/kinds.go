package queue

// The kinds of work this deployment queues.
//
// Here rather than each in the package that does the work, because the name of
// a job is shared between whoever adds it and whoever claims it, and those are
// deliberately different packages. Kept where they were, reading an accepted
// upload had to import the whole scanner package for one string — a dependency
// pointing backwards against the flow of the work, and one that would have made
// a second producer of scan jobs import it too.
//
// The strings themselves are stored in the queue table and read by a running
// deployment's rows, so they are not renamed casually: a rename leaves queued
// work nothing claims.
const (
	// Parse names the work an accepted upload leaves behind.
	Parse = "scan.read"
	// Scan names the work of scanning what a build contains.
	Scan = "vulnerability.scan"
	// Route names the work of applying the standing rules to what is already
	// open.
	Route = "routing.sweep"
)

// Kinds is every kind of work this deployment queues.
//
// For the one reader that asks about all of them rather than about its own: an
// operator looking at what is waiting. The cap is per kind, so a single number
// across the queue would hide the kind that is actually backed up behind the
// two that are not.
func Kinds() []string { return []string{Parse, Scan, Route} }
