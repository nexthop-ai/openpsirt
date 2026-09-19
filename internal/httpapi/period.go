package httpapi

import (
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// Period is the stretch of time a report is asked about.
//
// The default window differs per report and lives in each handler's call to
// window, so the operation that takes it says which in its own description:
// one struct tag cannot carry three answers.
//
// A rolling window cannot say "last financial year". A number of days ending
// now answers "how are we doing lately" and nothing else, and the two
// questions a manager and an auditor ask are how the quarter went and what the
// year on the certificate says. Those are a pair of dates.
//
// One struct, so every report over a stretch of time takes it the same way and
// a screen linking from one to another carries the same two parameters.
type Period struct {
	From string `query:"from" doc:"The first day of the period, as YYYY-MM-DD. Without an end the period runs to now"`
	To   string `query:"to" doc:"The day the period ends, as YYYY-MM-DD, and not itself in it. Without a start the period runs from the beginning"`
	Days int    `query:"days" minimum:"1" maximum:"3650" doc:"A rolling window of this many days ending now. An alternative to a period, not an addition to one"`
}

// window is the period as two moments, and what a report bounds by.
//
// A zero start is the beginning and a zero end is now, which is what a store
// takes for an unbounded side — so a report asked for nothing in particular
// answers about everything it holds unless it names a default window.
func (p Period) window(byDefault int, now time.Time) (time.Time, time.Time, error) {
	var since, until time.Time
	from, err := aDate(p.From)
	if err != nil {
		return since, until, err
	}
	to, err := aDate(p.To)
	if err != nil {
		return since, until, err
	}
	// Both ways of saying when, in one request. Refused rather than picked
	// between: a caller who sent both meant one of them, and a report that
	// silently answered about the other is a figure quoted for the wrong
	// period — which is the whole failure a period control exists to fix.
	if p.Days > 0 && (from != nil || to != nil) {
		return since, until, huma.Error422UnprocessableEntity(
			"a rolling window and a period are two ways of saying when: send days, " +
				"or from and to, and not both")
	}
	switch {
	case from != nil || to != nil:
		if from != nil {
			since = *from
		}
		// The end, resolved here rather than left to each store. A report
		// says the period back, and a start with no end answers "to: ''" over
		// figures that run all the way to now — the one field meant to make a
		// figure checkable saying nothing.
		until = now
		if to != nil {
			until = *to
		}
	case p.Days > 0:
		until = now
		since = now.AddDate(0, 0, -p.Days)
	case byDefault > 0:
		until = now
		since = now.AddDate(0, 0, -byDefault)
	}
	// A period with nothing in it, and a report answering zero for one is
	// indistinguishable from a quarter in which nothing happened. Two
	// refusals, because two dates the same way round is not a mistake about
	// direction: the end is not itself in the period, so naming one day twice
	// asks for no days at all.
	if !since.IsZero() && !until.IsZero() {
		if since.Equal(until) {
			return since, until, huma.Error422UnprocessableEntity(
				"the period holds no days: the end is not itself in it, so name a later one")
		}
		if since.After(until) {
			return since, until, huma.Error422UnprocessableEntity(
				"the period ends before it starts")
		}
	}
	return since, until, nil
}

// stating is the period as a report says it back, so a figure is never read
// without the window it was worked out over.
func stating(since, until time.Time) (string, string) {
	from, to := "", ""
	if !since.IsZero() {
		from = since.UTC().Format(time.DateOnly)
	}
	if !until.IsZero() {
		to = until.UTC().Format(time.DateOnly)
	}
	return from, to
}
